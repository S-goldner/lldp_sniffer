
#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <stdlib.h>
#include <string.h>
#include <drivers/eth/eth.h>
#include <lib/network/ping.h>

#define LLDP_TYPE 0x88CC
#define LLDP_DEST_MAC "\x01\x80\xc2\x00\x00\x0e"

typedef struct {
    char chassis_id[32];
    char port_id[32];
    uint16_t ttl;
} LldpInfo;

static void parse_lldp(const uint8_t* data, size_t len, LldpInfo* info) {
    memset(info, 0, sizeof(LldpInfo));
    const uint8_t* ptr = data;
    const uint8_t* end = data + len;

    while(ptr + 2 <= end) {
        uint16_t tlv_header = (ptr[0] << 8) | ptr[1];
        uint8_t type = (tlv_header >> 9) & 0x7F;
        uint16_t length = tlv_header & 0x1FF;
        ptr += 2;

        if(ptr + length > end) break;

        switch(type) {
            case 1: // Chassis ID
                if(length > 1 && ptr[0] == 4)
                    snprintf(info->chassis_id, sizeof(info->chassis_id), "%02X:%02X:%02X:%02X:%02X:%02X",
                             ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6]);
                break;
            case 2: // Port ID
                if(length > 1 && ptr[0] == 3)
                    snprintf(info->port_id, sizeof(info->port_id), "%02X:%02X:%02X:%02X",
                             ptr[1], ptr[2], ptr[3], ptr[4]);
                break;
            case 3: // TTL
                if(length == 2)
                    info->ttl = (ptr[0] << 8) | ptr[1];
                break;
            case 0: // End of LLDPDU
                return;
        }

        ptr += length;
    }
}

static void draw_callback(Canvas* canvas, void* ctx) {
    LldpInfo* info = ctx;
    canvas_draw_str(canvas, 0, 10, "LLDP Sniffer");
    canvas_draw_str(canvas, 0, 25, info->chassis_id[0] ? info->chassis_id : "Chassis: ?");
    canvas_draw_str(canvas, 0, 40, info->port_id[0] ? info->port_id : "Port: ?");
    char ttl_str[32];
    snprintf(ttl_str, sizeof(ttl_str), "TTL: %d", info->ttl);
    canvas_draw_str(canvas, 0, 55, ttl_str);
}

int32_t lldp_sniffer_app(void* p) {
    UNUSED(p);
    uint8_t frame[1600];
    size_t frame_len;
    LldpInfo info = {0};

    ViewPort* vp = view_port_alloc();
    view_port_draw_callback_set(vp, draw_callback, &info);

    Gui* gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(gui, vp, GuiLayerFullscreen);

    eth_init();

    while(1) {
        frame_len = eth_recv_frame(frame, sizeof(frame));
        if(frame_len >= 14) {
            uint16_t eth_type = (frame[12] << 8) | frame[13];
            if(eth_type == LLDP_TYPE &&
               memcmp(frame, LLDP_DEST_MAC, 6) == 0) {
                parse_lldp(frame + 14, frame_len - 14, &info);
                view_port_update(vp);
            }
        }

        InputEvent evt;
        while(input_poll(&evt)) {
            if(evt.type == InputTypePress && evt.key == InputKeyBack) goto exit;
            if(evt.type == InputTypePress && evt.key == InputKeyOk) {
                ping_result_t result = ping("google.com", 1000);
                if(result.success) info.ttl = 999;
                else info.ttl = 0;
                view_port_update(vp);
            }
        }

        furi_delay_ms(100);
    }

exit:
    eth_deinit();
    gui_remove_view_port(gui, vp);
    view_port_free(vp);
    furi_record_close(RECORD_GUI);
    return 0;
}
