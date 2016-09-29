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


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sysfs.h>

#include <linux/rio_drv.h>
#include <linux/rio_ids.h>

#include "riosocket.h"

unsigned long msgwatermark=DEFAULT_MSG_WATERMARK;

static ssize_t riosocket_show_msgwatermark(struct device_driver *ddp, char *buf)
{
         return snprintf(buf,PAGE_SIZE, "%ld\n", msgwatermark);
}

static ssize_t riosocket_store_msgwatermark(struct device_driver *ddp,
                                      const char *buf, size_t count)
{
	if(!kstrtoul(buf, 10, &msgwatermark)) {
		if( msgwatermark < 14 )
			msgwatermark=0;
		return count;
	} else {
		return 0;
	}
}

static DRIVER_ATTR(msgwatermark, S_IRUSR | S_IWUSR,
		riosocket_show_msgwatermark, riosocket_store_msgwatermark);


static ssize_t riosocket_show_txringfull(struct device_driver *ddp, char *buf)
{
         return snprintf(buf,PAGE_SIZE, "%ld\n", stats.txringfull);
}

static ssize_t riosocket_store_txringfull(struct device_driver *ddp,
                                      const char *buf, size_t count)
{
	if(!kstrtoul(buf, 10, &stats.txringfull))
		return count;
	else
		return 0;
}

static DRIVER_ATTR(txringfull, S_IRUSR | S_IWUSR,
		riosocket_show_txringfull, riosocket_store_txringfull);


static ssize_t riosocket_show_maxintransitpkt(struct device_driver *ddp, char *buf)
{
         return snprintf(buf,PAGE_SIZE, "%ld\n", stats.maxintransitpkt);
}

static ssize_t riosocket_store_maxintransitpkt(struct device_driver *ddp,
                                      const char *buf, size_t count)
{
	if(!kstrtoul(buf, 10, &stats.maxintransitpkt))
		return count;
	else
		return 0;
}

static DRIVER_ATTR(maxintransitpkt, S_IRUSR | S_IWUSR,
		riosocket_show_maxintransitpkt, riosocket_store_maxintransitpkt);


static ssize_t riosocket_show_numxmitmore(struct device_driver *ddp, char *buf)
{
         return snprintf(buf,PAGE_SIZE, "%ld\n", stats.numxmitmore);
}

static ssize_t riosocket_store_numxmitmore(struct device_driver *ddp,
                                      const char *buf, size_t count)
{
	if(!kstrtoul(buf, 10, &stats.numxmitmore))
		return count;
	else
		return 0;
}

static DRIVER_ATTR(numxmitmore, S_IRUSR | S_IWUSR,
		riosocket_show_numxmitmore, riosocket_store_numxmitmore);

static ssize_t riosocket_show_napisaturate(struct device_driver *ddp, char *buf)
{
         return snprintf(buf,PAGE_SIZE, "%ld\n", stats.napisaturate);
}

static ssize_t riosocket_store_napisaturate(struct device_driver *ddp,
                                      const char *buf, size_t count)
{
	if(!kstrtoul(buf, 10, &stats.napisaturate))
		return count;
	else
		return 0;
}

static DRIVER_ATTR(napisaturate, S_IRUSR | S_IWUSR,
		riosocket_show_napisaturate, riosocket_store_napisaturate);

static struct attribute *riosocket_drv_attrs[] = {
        &driver_attr_txringfull.attr,
		&driver_attr_maxintransitpkt.attr,
		&driver_attr_numxmitmore.attr,
		&driver_attr_napisaturate.attr,
		&driver_attr_msgwatermark.attr,
		NULL
};

static struct attribute_group riosocket_drv_attr_grp = {
        .attrs = riosocket_drv_attrs
};

const struct attribute_group *riosocket_drv_attr_groups[] = {
        &riosocket_drv_attr_grp,
        NULL,
};
