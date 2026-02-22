#include <minix/drivers.h>
#include <minix/driver.h>
#include <stdio.h>
#include <stdlib.h>
#include <minix/ds.h>

#include <sys/ioctl.h>
#include <sys/ucred.h>

#ifndef SECRET_SIZE
#define SECRET_SIZE 8192
#endif

#ifndef RBIT
#define RBIT 4
#endif

#ifndef WBIT
#define WBIT 2
#endif

/*
 * Function prototypes for the secret driver.
 */
FORWARD _PROTOTYPE( char * secret_name,   (void) );
FORWARD _PROTOTYPE( int secret_open,      (struct driver *d, message *m) );
FORWARD _PROTOTYPE( int secret_close,     (struct driver *d, message *m) );
FORWARD _PROTOTYPE( int secret_ioctl,     (struct driver *d, messega *m) );
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
PRIVATE int owned;

/* The uid of the owner of the secret */
PRIVATE uid_t owner;

/* The buffer that holds the current secret */
PRIVATE char secret_buf[SECRET_SIZE];

/* Helper that resets all the above data */
PRIVATE void secret_reset(void)
{
    open_counter = 0;
    read_once = 0;
    rpos = 0;
    wpos = 0;
    owned = 0;
    owner = 0;
}

/* Returns the name of this driver */
PRIVATE char * secret_name(void)
{
    printf("secret_name()\n");
    return "secretkeeper";
}

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
        return r;
    }

    if ((flags & (RBIT | WBIT)) == (RBIT | WBIT)) {
        return EACCES;
    }

    if (!secret_owner_valid) {
        
    printf("secret_open(). Called %d time(s).\n", ++open_counter);
    return OK;
}

PRIVATE int secret_close(d, m)
    struct driver *d;
    message *m;
{
    printf("secret_close()\n");
    return OK;
}

PRIVATE struct device * secret_prepare(dev)
    int dev;
{
    secret_device.dv_base.lo = 0;
    secret_device.dv_base.hi = 0;
    secret_device.dv_size.lo = 0;
    secret_device.dv_size.hi = 0;
    return &secret_device;
}

PRIVATE int secret_transfer(proc_nr, opcode, position, iov, nr_req)
    int proc_nr;
    int opcode;
    u64_t position;
    iovec_t *iov;
    unsigned nr_req;
{
    int bytes, ret;

    printf("secret_transfer()\n");

    bytes = strlen(SECRET_MESSAGE) - position.lo < iov->iov_size ?
            strlen(SECRET_MESSAGE) - position.lo : iov->iov_size;

    if (bytes <= 0)
    {
        return OK;
    }
    switch (opcode)
    {
        case DEV_GATHER_S:
            ret = sys_safecopyto(proc_nr, iov->iov_addr, 0,
                                (vir_bytes) (SECRET_MESSAGE + position.lo),
                                 bytes, D);
            iov->iov_size -= bytes;
            break;

        default:
            return EINVAL;
    }
    return ret;
}

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
    ds_publish_u32("open_counter", open_counter, DSF_OVERWRITE);

    return OK;
}

PRIVATE int lu_state_restore() {
/* Restore the state. */
    u32_t value;

    ds_retrieve_u32("open_counter", &value);
    ds_delete_u32("open_counter");
    open_counter = (int) value;

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
            printf("%s", SECRET_MESSAGE);
        break;

        case SEF_INIT_LU:
            /* Restore the state. */
            lu_state_restore();
            do_announce_driver = FALSE;

            printf("%sHey, I'm a new version!\n", SECRET_MESSAGE);
        break;

        case SEF_INIT_RESTART:
            printf("%sHey, I've just been restarted!\n", SECRET_MESSAGE);
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
 *      * Perform initialization.
 *           */
    sef_local_startup();

    /*
 *      * Run the main loop.
 *           */
    driver_task(&secret_tab, DRIVER_STD);
    return OK;
}
