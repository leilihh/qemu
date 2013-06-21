/*
 * QEMU localhost live migration
 *
 * Copyright IBM, Corp. 2013
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions are licensed under the terms of the GNU GPL, version 2
 * or (at your option) any later version.
 */

#include "qemu-common.h"
#include "migration/migration.h"
#include "monitor/monitor.h"
#include "migration/qemu-file.h"
#include "sysemu/sysemu.h"
#include "block/block.h"
#include "qemu/sockets.h"
#include "migration/block.h"
#include "qemu/thread.h"
#include "qmp-commands.h"
#include "exec/memory.h"
#include "trace.h"
#include "qemu/osdep.h"

//#define DEBUG_MIGRATION_LOCAL

#ifdef DEBUG_MIGRATION_LOCAL
#define DPRINTF(fmt, ...) \
    do { printf("migration-local: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif


/************************************************************************
 * Outgoing part
 */

static void *migration_local_thread(void *opaque)
{
    LocalMigState *s = opaque;
    int ret;
    ram_addr_t size;

    DPRINTF("Beginning savevm\n");

    /* This will be replaced by new function qemu_save_local_state(). */
    ret = qemu_save_device_state(s->file);
    qemu_fclose(s->file);

    if (ret < 0) {
        s->state = MIG_STATE_ERROR;
        return NULL;
    } else {
        /* XXX: The logic will be changed, need more work here. */
        s->state = MIG_STATE_COMPLETED;

        size = ram_bytes_total();
        ram_madvise_free(size);
    }

    return NULL;
}

void migrate_fd_connect_local(LocalMigState *s)
{
    s->state = MIG_STATE_ACTIVE;
    trace_migrate_set_state(MIG_STATE_ACTIVE);

    qemu_thread_create(&s->thread, migration_local_thread, s,
                       QEMU_THREAD_JOINABLE);
}

void qmp_localhost_migrate(const char *uri, Error **errp)
{
    const char *path;
    Error *local_err = NULL;
    int is_vm_running;
    LocalMigState *s;

    is_vm_running = runstate_is_running();

    /* Stop the VM first */
    if (is_vm_running) {
        vm_stop(RUN_STATE_SAVE_VM);
    }

    bdrv_flush_all();

    s = g_malloc0(sizeof(LocalMigState));

    /* Start outgoing migration by unix socket. */
    if (strstart(uri, "unix:", &path)) {
        /* XXX. Creat a new unix_start_outgoing_migration_* is not necessary,
         * just for the first step. This will be replaced by vmsplice
         * mechanism. */
        unix_start_local_outgoing_migration(s, path, &local_err);
    } else {
        error_set(errp, QERR_INVALID_PARAMETER_VALUE, "uri", "a valid migration protocol");
        goto fail;
    }

    if (local_err) {
        s->state = MIG_STATE_ERROR;
        error_propagate(errp, local_err);
        goto fail;
    }

fail:
    if (!is_vm_running) {
        vm_start();
    }
}

/**********************************************************************
 * Incoming part
 */

void qemu_start_local_incoming_migration(const char *uri, Error **errp)
{
    const char *p;

    if (strstart(uri, "unix:", &p)) {
        unix_start_local_incoming_migration(p, errp);
    } else {
        error_setg(errp, "unknown migration protocol: %s", uri);
    }
}

void start_local_incoming_migration(QEMUFile *f)
{
    int ret;

    ret = qemu_loadvm_state(f);
    if (ret < 0) {
        fprintf(stderr, "load of migration failed\n");
        exit(EXIT_FAILURE);
    }
    qemu_announce_self();

    DPRINTF("successfully loaded vm state\n");

    bdrv_clear_incoming_migration_all();
    /* Make sure all file formats flush their mutable metadata */
    bdrv_invalidate_cache_all();

    if (autostart) {
        vm_start();
    } else {
        runstate_set(RUN_STATE_PAUSED);
    }
}
