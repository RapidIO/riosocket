/*********************************************************************
 *  Copyright of Centaurus Computing - 2016
 * 
 *  This file is part of riosocket-basic.
 * 
 *  riosocket-basic is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *   
 *  riosocket-basic is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with riosocket-basic.  If not, see <http://www.gnu.org/licenses/>.
 *  
 *  *********************************************************************/

//#define DEBUG 1
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/crc32.h>
#include <linux/ethtool.h>
#include <linux/reboot.h>
#include <linux/version.h>

#include <linux/rio.h>
#include <linux/rio_drv.h>
#include <linux/rio_ids.h>

#include "riosocket.h"

/*Code reuse from RIONET for cleaner implementation of messaging based
 * smaller packet transfers*/

extern struct riosocket_network nets[MAX_NETS];

static int riosocket_rx_clean(struct net_device *ndev)
{
	int i;
	int error = 0;
	struct riosocket_private *priv = netdev_priv(ndev);
	struct riosocket_msg_private *rnet = &priv->rnetpriv;
	void *data;
	int msg_size;
	unsigned char *hdr;

	dev_dbg(&ndev->dev,"%s: Start\n",__FUNCTION__);

	i = rnet->rx_slot;

	do {
		if (!rnet->rx_skb[i])
			continue;

		if (!(data = rio_get_inb_message(rnet->mport, RIONET_MAILBOX,
						 &msg_size)))
			break;

		hdr = data;

		msg_size = (hdr[2] << 8) | hdr[1];

		if( hdr[0] == 0xFF ) {
			hdr[1] = 0xFF;
			hdr[2] = 0xFF;
		} else {
			hdr[1] = 0x00;
			hdr[2] = 0x00;
		}

		rnet->rx_skb[i]->data = data;
		skb_put(rnet->rx_skb[i], msg_size);
		rnet->rx_skb[i]->dev=ndev;
		rnet->rx_skb[i]->ip_summed=CHECKSUM_UNNECESSARY;
		rnet->rx_skb[i]->protocol =
			eth_type_trans(rnet->rx_skb[i], ndev);
		error = netif_rx(rnet->rx_skb[i]);

		if (error == NET_RX_DROP) {
				ndev->stats.rx_dropped++;
		} else {
				ndev->stats.rx_packets++;
				ndev->stats.rx_bytes += msg_size;
		}

	} while ((i = (i + 1) % RIONET_RX_RING_SIZE) != rnet->rx_slot);

	dev_dbg(&ndev->dev,"%s: End\n",__FUNCTION__);
	return i;
}

static void riosocket_rx_fill(struct net_device *ndev, int end)
{
	int i;
	struct riosocket_private *priv = netdev_priv(ndev);
	struct riosocket_msg_private *rnet = &priv->rnetpriv;

	dev_dbg(&ndev->dev,"%s: Start\n",__FUNCTION__);

	i = rnet->rx_slot;
	do {
		rnet->rx_skb[i] = dev_alloc_skb(RIO_MAX_MSG_SIZE);

		if (!rnet->rx_skb[i])
			break;

		rio_add_inb_buffer(rnet->mport, RIONET_MAILBOX,
				   rnet->rx_skb[i]->data);
	} while ((i = (i + 1) % RIONET_RX_RING_SIZE) != end);

	rnet->rx_slot = i;

	dev_dbg(&ndev->dev,"%s: End\n",__FUNCTION__);
}

static int riosocket_queue_tx_msg(struct sk_buff *skb, struct net_device *ndev,
			       struct rio_dev *rdev, int count)
{
	struct riosocket_private *priv = netdev_priv(ndev);
	struct riosocket_msg_private *rnet = &priv->rnetpriv;
	unsigned char *hdr = skb->data;

	dev_dbg(&ndev->dev,"%s: Start\n",__FUNCTION__);

	hdr[1] = (unsigned char)(skb->len & 0xFF);
	hdr[2] = (unsigned char)((skb->len >> 8) & 0xFF);

	rio_add_outb_message(rnet->mport, rdev, 0, skb->data, skb->len);
	rnet->tx_skb[rnet->tx_slot] = skb;

	ndev->stats.tx_packets++;
	ndev->stats.tx_bytes += skb->len;

	if (++rnet->tx_cnt == RIONET_TX_RING_SIZE)
		netif_stop_queue(ndev);

	++rnet->tx_slot;
	rnet->tx_slot &= (RIONET_TX_RING_SIZE - 1);

	if (count)
		atomic_inc(&skb->users);

	dev_dbg(&ndev->dev,"%s: End\n",__FUNCTION__);

	return 0;
}



void riosocket_inb_msg_event(struct rio_mport *mport, void *dev_id, int mbox, int slot)
{
	int n;
	struct net_device *ndev = dev_id;
	struct riosocket_private *priv = netdev_priv(ndev);
	struct riosocket_msg_private *rnet = &priv->rnetpriv;

	dev_dbg(&ndev->dev,"%s: Start\n",__FUNCTION__);

	spin_lock(&rnet->lock);
	if ((n = riosocket_rx_clean(ndev)) != rnet->rx_slot)
			riosocket_rx_fill(ndev, n);
	spin_unlock(&rnet->lock);

	dev_dbg(&ndev->dev,"%s: End\n",__FUNCTION__);
}

void riosocket_outb_msg_event(struct rio_mport *mport, void *dev_id, int mbox, int slot)
{
	struct net_device *ndev = dev_id;
	struct riosocket_private *priv = netdev_priv(ndev);
	struct riosocket_msg_private *rnet = &priv->rnetpriv;

	dev_dbg(&ndev->dev,"%s: Start\n",__FUNCTION__);

	spin_lock(&rnet->tx_lock);

	while (rnet->tx_cnt && (rnet->ack_slot != slot)) {
		/* dma unmap single */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0))
		dev_kfree_skb_irq(rnet->tx_skb[rnet->ack_slot]);
#else
		dev_consume_skb_irq(rnet->tx_skb[rnet->ack_slot]);
#endif
		rnet->tx_skb[rnet->ack_slot] = NULL;
		++rnet->ack_slot;
		rnet->ack_slot &= (RIONET_TX_RING_SIZE - 1);
		rnet->tx_cnt--;
	}

	if (rnet->tx_cnt < RIONET_TX_RING_SIZE)
		netif_wake_queue(ndev);

	spin_unlock(&rnet->tx_lock);

	dev_dbg(&ndev->dev,"%s: End\n",__FUNCTION__);
}

int riosocket_open(struct net_device *ndev)
{
	int i, rc = 0;
	struct riosocket_private *priv = netdev_priv(ndev);
	struct riosocket_msg_private *rnet = &priv->rnetpriv;

	dev_dbg(&ndev->dev,"%s: Start\n",__FUNCTION__);

	/* Initialize inbound message ring */
	for (i = 0; i < RIONET_RX_RING_SIZE; i++)
		rnet->rx_skb[i] = NULL;

	rnet->rx_slot = 0;
	riosocket_rx_fill(ndev, 0);

	rnet->tx_slot = 0;
	rnet->tx_cnt = 0;
	rnet->ack_slot = 0;

	dev_dbg(&ndev->dev,"%s: End\n",__FUNCTION__);
	return rc;
}

int riosocket_close(struct net_device *ndev)
{
	int i=0;
	struct riosocket_private *priv = netdev_priv(ndev);
	struct riosocket_msg_private *rnet = &priv->rnetpriv;

	dev_dbg(&ndev->dev,"%s: Start\n",__FUNCTION__);

	for (i = 0; i < RIONET_RX_RING_SIZE; i++)
			kfree_skb(rnet->rx_skb[i]);

	dev_dbg(&ndev->dev,"%s: End\n",__FUNCTION__);

	return 0;
}

int riosocket_start_xmit_msg(struct sk_buff *skb, struct net_device *ndev)
{
	struct riosocket_private *priv = netdev_priv(ndev);
	struct riosocket_msg_private *rnet = &priv->rnetpriv;
	struct ethhdr *eth = (struct ethhdr *)skb->data;
	unsigned int destid=riosocket_get_node_id_from_mac(eth->h_dest);
	struct riosocket_node *node;
	unsigned long flags;

	dev_dbg(&ndev->dev,"%s: Start\n",__FUNCTION__);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0))
        local_irq_save(flags);
        if (!spin_trylock(&rnet->tx_lock)) {
                local_irq_restore(flags);
                return NETDEV_TX_LOCKED;
        }
#else
	spin_lock_irqsave(&rnet->tx_lock, flags);
#endif

	if ((rnet->tx_cnt+1)  > RIONET_TX_RING_SIZE) {
		netif_stop_queue(ndev);
		spin_unlock_irqrestore(&rnet->tx_lock,flags);
		return NETDEV_TX_BUSY;
	}

	if ( destid == BROADCAST || is_multicast_ether_addr(eth->h_dest)) {
		int count = 0;

		spin_lock(&nets[priv->netid].lock);
		list_for_each_entry(node,
				 &nets[priv->netid].actnodelist, nodelist) {

			if (node->ready) {
				dev_dbg(&ndev->dev,"%s: Sending broadcast message to node %d\n",
								__FUNCTION__,node->devid);
				riosocket_queue_tx_msg(skb, ndev, node->rdev,count);
				count++;
			}
		}
		spin_unlock(&nets[priv->netid].lock);
	} else {

		node = riosocket_get_node_id(&nets[priv->netid].actnodelist,destid);

		if (node && node->ready) {
			dev_dbg(&ndev->dev,"%s: Sending message to node %d\n",__FUNCTION__,
										node->devid);
			riosocket_queue_tx_msg(skb, ndev,node->rdev,0);
		} else {
			dev_kfree_skb_irq(skb);
			ndev->stats.tx_dropped++;
		}
	}

	spin_unlock_irqrestore(&rnet->tx_lock,flags);
	dev_dbg(&ndev->dev,"%s: End\n",__FUNCTION__);
	return NETDEV_TX_OK;
}
