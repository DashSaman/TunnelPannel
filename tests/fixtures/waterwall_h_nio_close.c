/* Pinned DashSaman/WaterWall-H 613bb32c93db40b09cb915070e5f7ff09ad3c81d.
 * MPL-2.0: https://mozilla.org/MPL/2.0/
 * Exact owner-worker close function from ww/event/nio.c. */
int wioClose(wio_t *io)
{
    // if (io->destroy == 0 && getTID() != io->loop->tid) {
    //     return wioCloseAsync(io); /*  tid lost its meaning, its now ww tid */
    // }

    if (io->closed)
    {

        return 0;
    }
    if (! write_queue_empty(&io->write_queue) && io->error == 0 && io->close == 0 && io->destroy == 0)
    {
        io->close = 1;

        wlogd("write_queue not empty, close later.");
        int timeout_ms  = io->close_timeout ? io->close_timeout : WIO_DEFAULT_CLOSE_TIMEOUT;
        io->close_timer = wtimerAdd(io->loop, __close_timeout_cb, (uint32_t) timeout_ms, 1);
        if (UNLIKELY(io->close_timer == NULL))
        {
            io->close = 0;
            io->error = ECANCELED;
        }
        else
        {
            io->close_timer->privdata = io;
            return 0;
        }
    }
    // bool has_pending = io->pending;

    const bool freeing    = io->destroy;
    io->close_in_progress = 1;
    io->closed = 1;
    // wloop_t *loop = io->loop;

    wioDone(io);
    __close_cb(io);
    wioReleaseFD(io, false);
    io->close_in_progress = 0;
    if (io->destroy && ! freeing)
    {
        wioFinalizeNow(io);
    }

    return 0;
}

