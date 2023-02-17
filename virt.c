#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netdev_features.h>

static struct net_device *virtual_net;

static void virtual_net_rs_packet(struct sk_buff *skb, struct net_device *dev)
{
    unsigned char *type;
    struct iphdr *ih;
    __be32 *saddr, *daddr, tmp;
    unsigned char tmp_dev_addr[ETH_ALEN];
    struct ethhdr *ethhdr;
    struct sk_buff *rx_skb;
    int ret;

    // 对调ethhdr结构体 "源/目的"MAC地址*/
    ethhdr = (struct ethhdr *)skb->data;
    memcpy(tmp_dev_addr, ethhdr->h_dest, ETH_ALEN);
    memcpy(ethhdr->h_dest, ethhdr->h_source, ETH_ALEN);
    memcpy(ethhdr->h_source, tmp_dev_addr, ETH_ALEN);

    // 对调iphdr结构体"源/目的" IP地址
    ih = (struct iphdr *)(skb->data + sizeof(struct ethhdr));
    saddr = &ih->saddr;
    daddr = &ih->daddr;
    tmp = *saddr;
    *saddr = *daddr;
    *daddr = tmp;

    ih->check = 0;
    ih->check = ip_fast_csum((unsigned char *)ih, ih->ihl);

    // 之前是发送ping包0x08,需要改为0x00,表示接收ping包
    type = skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    *type = 0;

    rx_skb = dev_alloc_skb(skb->len + 2);
    skb_reserve(rx_skb, 2);

    memcpy(skb_put(rx_skb, skb->len), skb->data, skb->len);
    rx_skb->dev = dev;
    rx_skb->ip_summed = CHECKSUM_UNNECESSARY;
    rx_skb->protocol = eth_type_trans(rx_skb, dev);
    ret = netif_rx(rx_skb);

    dev->stats.rx_packets++;
    dev->stats.rx_bytes += skb->len;
    pr_info("rx_packets=%ld rx_bytes=%ld ret=%d\n", dev->stats.rx_packets, dev->stats.rx_bytes, ret);
}

static int virtual_net_send_packet(struct sk_buff *skb, struct net_device *dev)
{
    netif_stop_queue(dev);
    virtual_net_rs_packet(skb, dev);
    dev_kfree_skb(skb);
    dev->stats.tx_packets++;
    dev->stats.tx_bytes += skb->len;
    pr_info("tx_packets=%ld tx_bytes=%ld\n", dev->stats.tx_packets, dev->stats.tx_bytes);
    netif_wake_queue(dev);
    return NETDEV_TX_OK;
}

static int set_mac_address(struct net_device *dev, void *p)
{
    struct sockaddr *addr = p;
    pr_info("set_mac_address\n");
    if (netif_running(dev))
    {
        return -EBUSY;
    }
    memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
    return 0;
}
void virtual_net_tx_timeout(struct net_device *net, unsigned int txqueue)
{
    pr_info("virtual_net_tx_timeout\n");
}

static const struct net_device_ops net_ops =
    {
        .ndo_start_xmit = virtual_net_send_packet,
        .ndo_set_mac_address = set_mac_address,
        .ndo_tx_timeout = virtual_net_tx_timeout,
};

static int virtual_net_init(void)
{
    virtual_net = alloc_netdev(sizeof(struct net_device), "virtual_net", NET_NAME_UNKNOWN, ether_setup);
    virtual_net->netdev_ops = &net_ops;
    virtual_net->flags = IFF_NOARP;

    virtual_net->dev_addr[0] = 0x88;
    virtual_net->dev_addr[1] = 0x88;
    virtual_net->dev_addr[2] = 0x88;
    virtual_net->dev_addr[3] = 0x88;
    virtual_net->dev_addr[4] = 0x88;
    virtual_net->dev_addr[5] = 0x88;

    register_netdev(virtual_net);
    return 0;
}

static void virtual_net_exit(void)
{
    unregister_netdev(virtual_net);
    free_netdev(virtual_net);
}

module_init(virtual_net_init);
module_exit(virtual_net_exit);

MODULE_LICENSE("MIT");
MODULE_AUTHOR("wwhai");
MODULE_DESCRIPTION("A simple virtual network module");
MODULE_ALIAS("virtual-network");
MODULE_VERSION("V1.0.0");