/*********************************************************************
 * Copyright of Centaurus Computing - 2016
 *
 * This file is part of riosocket-basic.
 *
 * riosocket-basic is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * riosocket-basic is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with riosocket-basic.  If not, see <http://www.gnu.org/licenses/>.
 *
 * ********************************************************************/

#define RIOSOCKET_VERSION		"1.01.01"
#define TSI721_VENDOR_ID                0x0038
#define TSI721_DEVICE_ID                0x80AB

#define MAX_NETS			8
#define DEFAULT_DOORBELL_BASE		0xe000
#define NAPI_WEIGHT			8
#define RIOSOCKET_HEADER		8
#define DEFAULT_MSG_WATERMARK		256
#define RIONET_MAILBOX			0

#define RIONET_TX_RING_SIZE		512
#define RIONET_RX_RING_SIZE		512

#define DB_START			0x0000
#define DB_HELLO     			0x0001
#define DB_HELLO_ACK_1 			0x0002
#define DB_HELLO_ACK_2			0x0003
#define DB_PKT_RXED			0x0005
#define DB_BYE				0x0006
#define DB_UPD_RD_CNT			0x0007
#define DB_END                    	0xFFFF
#define DB_CMD_MASK			0x000F
#define CMD_SHIFT			0x4

#define MAILBOX              		0

#define MAX_MTU                         65500
#define NODE_SECTOR_SIZE       		0x10000
#define NODE_MEMLEN                 	0x200000
#define DEFAULT_IBW_SIZE		0x8000000 /* 128MB IBW = 64 nodes */
#define DEFAULT_RIO_BASE		0 /* must be within first 16GB of addr space */

#define BROADCAST			0xFFFFFFFF

#define GET_DESTID(x)			((*((u8 *)x + 4) << 8) | *((u8 *)x + 5))

/*Code reuse from RIONET */
struct riosocket_msg_private {
	struct rio_mport *mport;
	struct sk_buff *rx_skb[RIONET_RX_RING_SIZE];
	struct sk_buff *tx_skb[RIONET_TX_RING_SIZE];
	int rx_slot;
	int tx_slot;
	int tx_cnt;
	int ack_slot;
	spinlock_t lock;
	spinlock_t tx_lock;
};

struct riosocket_driver_params
{
	unsigned long txringfull;
	unsigned long napisaturate;
	unsigned long numxmitmore;
	unsigned long maxintransitpkt;
	unsigned long transitpktcount;
};

struct riosocket_private {
        struct rio_mport *mport;
        struct riosocket_msg_private rnetpriv;
        unsigned char netid;
        unsigned char link;
};

struct riosocket_node {
        struct list_head nodelist;
        struct list_head mclist;
        struct rio_dev *rdev;
        struct net_device *ndev;
        struct resource *db_res;
        struct napi_struct napi;
        unsigned int netid;
    	unsigned int devid;
    	unsigned char ready;
    	unsigned char hellorxed;
    	unsigned long long rioaddress;
    	dma_addr_t buffer_address;
    	void *local_ptr;
    	unsigned char posted_write;
    	unsigned char act_write;
    	unsigned char act_read;
    	unsigned char mem_write;
    	unsigned char mem_read;
    	unsigned char ringsize;
};

struct riosocket_network {
        struct net_device   *ndev;
        struct list_head actnodelist;
        spinlock_t lock;
        struct rio_mport *mport;
        struct dma_chan *dmachan;
        unsigned int id;
	dma_addr_t dma_base;
};

struct riocket_rxparam
{
        struct riosocket_node *node;
        struct sk_buff *skb;
        struct scatterlist sgl;
        unsigned char kick;
};

static inline struct riosocket_node* riosocket_get_node(
				struct list_head *nlist, struct rio_dev *rdev)
{
	struct riosocket_node *node;
	list_for_each_entry(node, nlist, nodelist)
		if (node->rdev == rdev)
			return node;
	return NULL;
}

static inline struct riosocket_node* riosocket_get_node_id(
				struct list_head *nlist, unsigned int id)
{
	struct riosocket_node *node;
	list_for_each_entry(node, nlist, nodelist)
		if (node->rdev->destid == id)
			 return node;
	return NULL;
}

inline static unsigned int riosocket_get_node_id_from_mac(char *macAddr)
{
	unsigned char arr[] = { 0xC2,00,00,00 };

	if( !memcmp( macAddr , arr , (ETH_ALEN-2)) )
    	{
    		return GET_DESTID(macAddr);
    	}

    	return BROADCAST;
}

inline static void riosocket_pkt_dump( char *data, int len )
{
	int i=0;

	printk(KERN_INFO "Pkt Size:%d",len);
	for( i=0; i < len; i+=4 ) {
		printk(KERN_INFO "%02x %02x %02x %02x",data[i],data[i+1],data[i+2],data[i+3]);
	}
}

extern struct riosocket_driver_params stats;
int riosocket_netinit( struct riosocket_network *net );
int riosocket_netdeinit( struct riosocket_network *net );
int riosocket_node_napi_init( struct riosocket_node *peer );
int riosocket_node_napi_deinit( struct riosocket_node *node );
void riosocket_send_hello_msg( unsigned char netid );
void riosocket_send_bye_msg( unsigned char netid );
int riosocket_send_packet( unsigned int netid, unsigned int destid, struct sk_buff *skb );
int riosocket_send_broadcast( unsigned int netid, struct sk_buff *skb );
int riosocket_packet_drain( struct riosocket_node *node, int budget );
int riosocket_start_xmit_msg(struct sk_buff *skb, struct net_device *ndev);
int riosocket_open(struct net_device *ndev);
int riosocket_close(struct net_device *ndev);
void riosocket_inb_msg_event(struct rio_mport *mport, void *dev_id, int mbox, int slot);
void riosocket_outb_msg_event(struct rio_mport *mport, void *dev_id, int mbox, int slot);
