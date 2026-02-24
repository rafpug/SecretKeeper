/*  SOURCE FILE: secretkeeper.c
 *
 *  This is a character device driver that holds a secret.
 *  The secret can only be read by the owner of the secret
 *  When the device is unowned, whoever writes the secret
 *  first becomes the owner.
 *
 *  Owners of a secret can read their secret, but once the secret
 *  has been read atleast once and all open file descriptors are closed
 *  then the device resets to be unowned and no longer holds a secret 
 *
 *  Ownership can be transfered by the owner with ioctl() */

#include <minix/drivers.h>
#include <minix/driver.h>
#include <stdio.h>
#include <stdlib.h>
#include <minix/ds.h>

#include <sys/ioctl.h>
#include <sys/ucred.h>
#include <minix/const.h>

#ifndef SECRET_SIZE
#define SECRET_SIZE 8192
#endif

/* Default value of the boolean that represents the unowned state */
#define UNOWNED 0

/* Default value of the boolean that represents the unread state */
#define UNREAD 0

/*
 * Function prototypes for the secret driver.
 */
FORWARD _PROTOTYPE( char * secret_name,   (void) );
FORWARD _PROTOTYPE( int secret_open,      (struct driver *d, message *m) );
FORWARD _PROTOTYPE( int secret_close,     (struct driver *d, message *m) );
FORWARD _PROTOTYPE( int secret_ioctl,     (struct driver *d, message *m) );
FORWARD _PROTOTYPE( struct device * secret_prepare, (int device) );
FORWARD _PROTOTYPE( int secret_transfer,  (int procnr, int opcode,
                                          u64_t position, iovec_t *iov,
                                          unsigned nr_req) );
FORWARD _PROTOTYPE( void secret_geometry, (struct partition *entry) );

/* SEF functions and variables. */
FORWARD _PROTOTYPE( void sef_local_startup, (void) );
FORWARD _PROTOTYPE( int sef_cb_init, (int type, sef_init_info_t *info) );
FORWARD _PROTOTYPE( int sef_cb_lu_state_save, (int) );
FORWARD _PROTOTYPE( int lu_state_restore, (void) );

/* Entry points to the secret driver. */
PRIVATE struct driver secret_tab =
{
    secret_name,
    secret_open,
    secret_close,
    secret_ioctl,
    secret_prepare,
    secret_transfer,
    nop_cleanup,
    secret_geometry,
    nop_alarm,
    nop_cancel,
    nop_select,
    nop_ioctl,
    do_nop,
};

/* Represents the /dev/secret device. */
PRIVATE struct device secret_device;

/* State variable to count the number of times the device has been opened. */
PRIVATE int open_counter;

/* Boolean that indicates whether the secret has been read atleast once */
PRIVATE int read_once;

/* The amount of bytes read from the current buffer */
PRIVATE size_t rpos;

/* The amount of bytes written to the current buffer */
PRIVATE size_t wpos;

/* Boolean that indicates whether the secret is owned */
PRIVATE int secret_owned;

/* The uid of the owner of the secret */
PRIVATE uid_t secret_owner;

/* The buffer that holds the current secret */
PRIVATE char secret_buf[SECRET_SIZE];

/* Helper that resets all the above data */
PRIVATE void secret_reset(void)
{
    open_counter = 0;
    read_once = UNREAD;
    rpos = 0;
    wpos = 0;
    secret_owned = UNOWNED;
    secret_owner = 0;
}

/* Returns the name of this driver */
PRIVATE char * secret_name(void)
{
    printf("secret_name()\n");
    return "secretkeeper";
}

/* Either accepts or rejects the attempt to open the secret depending
 * on the given flags, owner of the secret, and user trying to open */ 
PRIVATE int secret_open(d, m)
    struct driver *d;
    message *m;
{
    int flags = m->COUNT;
    struct ucred cred;
    int r;
    endpoint_t who = m->IO_ENDPT;

    r = getnucred(who, &cred);
    if (r != OK) {
        /* Returns errno from getnucred failing */
        return -r;
    }

    if ((flags & (R_BIT | W_BIT)) == (R_BIT | W_BIT)) {
        /* Reject opening for read-write access */
        return EACCES;
    }

    if (secret_owned == UNOWNED) {
        /* Opening with either read or write succeeds when
         * secret is unowned */ 
        if (flags & W_BIT) {
            /* Whoever writes first becomes the new owner */
            secret_owned = !UNOWNED;
            secret_owner = cred.uid;
        }
        open_counter++;
        return OK;
    }
    else {
        if (flags & W_BIT) {
            /* Opening with write fails when secret is owned */
            return ENOSPC;
        }

        if ((flags & R_BIT) && cred.uid != secret_owner) {
            /* Opening with read fails when owner doesn't match */
            return EACCES;
        }

        read_once = !UNREAD;
        open_counter++;
        return OK;
    }    
}

/* Decrements the open_counter and resets everything once it reaches zero
 * and the secret was read once */
PRIVATE int secret_close(d, m)
    struct driver *d;
    message *m;
{
    if (open_counter > 0) {
        open_counter--;
    }
    
    if (open_counter <= 0 && read_once == !UNREAD) {
        secret_reset();
    }
    
    printf("secret_close()\n");
    return OK;
}

/* Since this is a char device, nothing should use this */
PRIVATE struct device * secret_prepare(dev)
    int dev;
{
    secret_device.dv_base.lo = 0;
    secret_device.dv_base.hi = 0;
    secret_device.dv_size.lo = 0;
    secret_device.dv_size.hi = 0;
    return &secret_device;
}

/* Switches the ownership of the secret as requested by the owner */
PRIVATE int secret_ioctl(struct driver *d, message *m)
{
    int req = m->REQUEST;
    struct ucred cred;
    int r;
    uid_t grantee;

    if (req != SSGRANT) {
        /* Rejects all ioctl requests aside from SSGRANT */
        return ENOTTY;
    }
    
    r = getnucred(m->IO_ENDPT, &cred);
    if (r != OK) {
        return -r;
    }

    if (secret_owned == UNOWNED || cred.uid != secret_owner) {
        return EACCES;
    }

    r = sys_safecopyfrom(m->IO_ENDPT, (vir_bytes)m->IO_GRANT, 0,
                (vir_bytes) &grantee, sizeof(grantee), D);
    if (r != OK) {
        return -r;
    }

    secret_owner = grantee;
    return OK;
}

/* Read/writes to the secret buffer */
PRIVATE int secret_transfer(proc_nr, opcode, position, iov, nr_req)
    int proc_nr;
    int opcode;
    u64_t position;
    iovec_t *iov;
    unsigned nr_req;
{
    size_t bytes;
    int ret;

    printf("secret_transfer()\n");

    switch (opcode)
    {
        case DEV_GATHER_S:
            if (secret_owned == UNOWNED) {
                /* No secret to read */
                return OK;
            }
        
            if (rpos >= wpos) {
                /* Reached the end of written secret */
                return OK;
            }

            bytes = iov->iov_size;
            if (bytes > (wpos - rpos)){
                bytes = (wpos - rpos);
            }

            if (!bytes) {
                return OK;
            }

            ret = sys_safecopyto(proc_nr, iov->iov_addr, 0,
                                (vir_bytes) (secret_buf + rpos),
                                 bytes, D);
            if (ret != OK) {
                return ret;
            }
            rpos += bytes;
            iov->iov_size -= bytes;
            break;
        
        case DEV_SCATTER_S:
            if (wpos >= SECRET_SIZE) {
                return ENOSPC;
            }

            bytes = iov->iov_size;
            if (bytes > (SECRET_SIZE - wpos)){
                bytes = SECRET_SIZE - wpos;
            }

            if (bytes <= 0) {
                return ENOSPC;
            }

            ret = sys_safecopyfrom(proc_nr, iov->iov_addr, 0,
                                (vir_bytes)(secret_buf + wpos), bytes, D);
            if (ret != OK) {
                return ret;
            }
        
            wpos += bytes;
            iov->iov_size -= bytes;
            break;

        default:
            return EINVAL;
    }
    return OK;
}

/* Not used by anything */
PRIVATE void secret_geometry(entry)
    struct partition *entry;
{
    printf("secret_geometry()\n");
    entry->cylinders = 0;
    entry->heads     = 0;
    entry->sectors   = 0;
}

PRIVATE int sef_cb_lu_state_save(int state) {
/* Save the state. */
    int ret;

    ret = ds_publish_mem("open_counter", &open_counter, sizeof(int),
                            DSF_OVERWRITE);
    if (ret != OK) {
        return ret;
    }

    ret = ds_publish_mem("wpos", &wpos, sizeof(size_t), DSF_OVERWRITE);
    if (ret != OK) {
        return ret;
    }

    ret = ds_publish_mem("rpos", &rpos, sizeof(size_t), DSF_OVERWRITE);
    if (ret != OK) {
        return ret;
    }

    ret = ds_publish_mem("secret_owner", &secret_owner, sizeof(uid_t), 
                            DSF_OVERWRITE);
    if (ret != OK) {
        return ret;
    }

    ret = ds_publish_mem("secret_owned", &secret_owned, sizeof(int), 
                            DSF_OVERWRITE);
    if (ret != OK) {
        return ret;
    }

    ret = ds_publish_mem("read_once", &read_once, sizeof(int), DSF_OVERWRITE);
    if (ret != OK) {
        return ret;
    }

    ret = ds_publish_mem("secret_buf", secret_buf, SECRET_SIZE, DSF_OVERWRITE);
    if (ret != OK) {
        return ret;
    }

    return OK;
}

/* Helper that retrieves and deletes a stored value */
PRIVATE int restore_wrapper(char *name, void *vaddr, size_t length) {
    int ret;
    ret = ds_retrieve_mem(name, (char *) vaddr, &length);
    ds_delete_mem(name);
    return ret;
}
    

PRIVATE int lu_state_restore() {
/* Restore the state. */
    int ret;

    ret = restore_wrapper("open_counter",&open_counter, sizeof(int));
    if (ret != OK) {
        secret_reset();
        return ret;
    }

    ret = restore_wrapper("secret_owned",&secret_owned, sizeof(int));
    if (ret != OK) {
        secret_reset();
        return ret;
    }

    ret = restore_wrapper("read_once", &read_once, sizeof(int));
    if (ret != OK) {
        secret_reset();
        return ret;
    }
    
    
    ret = restore_wrapper("wpos", &wpos, sizeof(size_t));
    if (ret != OK) {
        secret_reset();
        return ret;
    }

    ret = restore_wrapper("rpos", &rpos, sizeof(size_t));
    if (ret != OK) {
        secret_reset();
        return ret; 
    }
    
    ret = restore_wrapper("secret_buf", secret_buf, SECRET_SIZE);
    if (ret != OK) {
        secret_reset();
        return ret;
    }

    return OK;
}

PRIVATE void sef_local_startup()
{
    /*
 *      * Register init callbacks. Use the same function for all event types
 *           */
    sef_setcb_init_fresh(sef_cb_init);
    sef_setcb_init_lu(sef_cb_init);
    sef_setcb_init_restart(sef_cb_init);

    /*
 *      * Register live update callbacks.
 *           */
    /* - Agree to update immediately when LU is requested in a valid state. */
    sef_setcb_lu_prepare(sef_cb_lu_prepare_always_ready);
    /* - Support live update starting from any standard state. */
    sef_setcb_lu_state_isvalid(sef_cb_lu_state_isvalid_standard);
    /* - Register a custom routine to save the state. */
    sef_setcb_lu_state_save(sef_cb_lu_state_save);

    /* Let SEF perform startup. */
    sef_startup();
}

PRIVATE int sef_cb_init(int type, sef_init_info_t *info)
{
/* Initialize the hello driver. */
    int do_announce_driver = TRUE;

    open_counter = 0;
    switch(type) {
        case SEF_INIT_FRESH:
            secret_reset();
        break;

        case SEF_INIT_LU:
            /* Restore the state. */
            lu_state_restore();
            do_announce_driver = FALSE;
        break;

        case SEF_INIT_RESTART:
            secret_reset();
        break;
    }

    /* Announce we are up when necessary. */
    if (do_announce_driver) {
        driver_announce();
    }

    /* Initialization completed successfully. */
    return OK;
}

PUBLIC int main(int argc, char **argv)
{
    /*
     * Perform initialization.
     */
    sef_local_startup();

    /*
     * Run the main loop.
     */
    driver_task(&secret_tab, DRIVER_STD);
    return OK;
}
