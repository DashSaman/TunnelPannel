/* WaterWall-H pinned 613bb32c93db40b09cb915070e5f7ff09ad3c81d.
 * MPL-2.0: see licenses/WaterWall-H-MPL-2.0.txt.
 * Exact upstream receive function used to test the applied source patch. */
bool httpclientTransportFeedHttp2Input(tunnel_t *t, line_t *l, httpclient_lstate_t *ls, sbuf_t *buf)
{
    uint32_t       len = sbufGetLength(buf);
    const uint8_t *ptr = (const uint8_t *) sbufGetRawPtr(buf);

    while (len > 0)
    {
        size_t        feed_len = min((size_t) len, (size_t) kHttpClientNghttp2RecvChunkBytes);
        nghttp2_ssize ret      = nghttp2_session_mem_recv2(ls->session, ptr, feed_len);
        if (ret < 0)
        {
            LOGE("HttpClient: nghttp2_session_mem_recv2 failed (%zd)", ret);
            lineReuseBuffer(l, buf);
            return false;
        }

        if (ret == 0)
        {
            LOGE("HttpClient: nghttp2_session_mem_recv2 consumed 0 bytes");
            lineReuseBuffer(l, buf);
            return false;
        }

        if ((size_t) ret > feed_len)
        {
            LOGE("HttpClient: nghttp2_session_mem_recv2 consumed beyond feed size (%zd > %zu)", ret, feed_len);
            lineReuseBuffer(l, buf);
            return false;
        }

        ptr += (size_t) ret;
        len -= (uint32_t) ret;
    }

    lineReuseBuffer(l, buf);

    if (! httpclientTransportMaybeSubmitWebSocketHttp2Request(t, l, ls))
    {
        return false;
    }

    if (! sendNghttp2Outbound(t, l, ls))
    {
        return false;
    }

    httpclient_tstate_t *ts = tunnelGetState(t);
    if (! ts->websocket_enabled)
    {
        if (! drainDownEvents(t, l, ls))
        {
            return false;
        }
    }

    if (ts->websocket_enabled && ls->websocket_h2_request_submitted && ls->h2_headers_received &&
        ! ls->websocket_active)
    {
        LOGE("HttpClient: websocket HTTP/2 handshake failed status_seen=%s status=%d protocol_seen=%s protocol=%s "
             "extensions_seen=%s extensions=%s",
             boolToTrueFalse(ls->websocket_h2_status_seen),
             ls->websocket_h2_status_code,
             boolToTrueFalse(ls->websocket_h2_protocol_seen),
             ls->websocket_h2_protocol_seen ? ls->websocket_h2_protocol : "<none>",
             boolToTrueFalse(ls->websocket_h2_extensions_seen),
             ls->websocket_h2_extensions_seen ? ls->websocket_h2_extensions : "<none>");
        return false;
    }

    if (ts->websocket_enabled && ls->websocket_active)
    {
        ls->websocket_waiting_handshake = false;
        if (ts->verbose)
        {
            LOGD("HttpClient: websocket HTTP/2 handshake accepted stream_id=%d protocol=%s",
                 ls->h2_stream_id,
                 ls->websocket_h2_protocol_seen ? ls->websocket_h2_protocol : "<none>");
        }
        if (! httpclientTransportDrainWebSocketDown(t, l, ls))
        {
            return false;
        }
        if (! httpclientTransportFlushPendingUp(t, l, ls))
        {
            return false;
        }
    }

    return true;
}


