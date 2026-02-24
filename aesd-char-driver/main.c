/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/slab.h>	
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Austin Friesenhahn");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

static int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev;

    PDEBUG("open");
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;

    return 0;
}

static int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    return 0;
}

static ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry;
    size_t entry_offset;
    size_t bytes_to_copy;
    size_t total_copied = 0;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

    if (!buf || !f_pos) {
        return -EINVAL;
    }

    if (*f_pos < 0) {
        return -EINVAL;
    }

    if (count == 0) {
        return 0;
    }

    if (mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }


    while (total_copied < count) {

        /* Obtain entry and offset corresponsidng to current fpos */
        entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->circular_buffer, (size_t)(*f_pos), &entry_offset);

        if (!entry) {
            break;
        }

        /* Copy as much as possible from given entry. 
           Either the rest of the entry or the amount requested by userspace */
        bytes_to_copy = min(entry->size - entry_offset, count - total_copied);

        /* Copy bytes to user buffer */
        if (copy_to_user(buf + total_copied, entry->buffptr + entry_offset, bytes_to_copy)) {
            retval = -EFAULT;
            goto out;
        }

        total_copied += bytes_to_copy;
        *f_pos += bytes_to_copy;
    }

    retval = total_copied;

  out:
    mutex_unlock(&dev->lock);
    return retval;
}

static ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    char* buffptr = NULL;
    const char* replaced_buffptr = NULL;
    struct aesd_buffer_entry new_entry;
    struct aesd_dev *dev = filp->private_data;

    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);

    if (mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }

    buffptr = kmalloc(count, GFP_KERNEL);
    if (!buffptr)
        goto out;

    if (copy_from_user(buffptr, buf, count)) {
        retval = -EFAULT;
        kfree(buffptr);
        goto out;
    }

    new_entry.buffptr = buffptr;
    new_entry.size = count;

    replaced_buffptr = aesd_circular_buffer_add_entry(&dev->circular_buffer, &new_entry);
    if (replaced_buffptr) {
        kfree(replaced_buffptr);
    }

    retval = count;

  out:
    mutex_unlock(&dev->lock);
    return retval;
}

static const struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}


static int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    aesd_major = MAJOR(dev);

    memset(&aesd_device,0,sizeof(struct aesd_dev));
    mutex_init(&aesd_device.lock);
    aesd_circular_buffer_init(&aesd_device.circular_buffer);

    result = aesd_setup_cdev(&aesd_device);
    if  (result) {
        unregister_chrdev_region(dev, 1);
    }
    return result;
}

static void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);
    int i = 0;
    struct aesd_buffer_entry *entry;

    cdev_del(&aesd_device.cdev);

    mutex_lock(&aesd_device.lock);
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.circular_buffer, i) {
        kfree(entry->buffptr);
        entry->buffptr = NULL;
        entry->size = 0;
    }
    mutex_unlock(&aesd_device.lock);

    unregister_chrdev_region(devno, 1);
}


module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
