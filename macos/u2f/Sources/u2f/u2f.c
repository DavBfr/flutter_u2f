#include "u2f.h"

// The Dart FFI bindings resolve the hidapi symbols at runtime: from
// `hidapi.framework` when the plugin is installed with CocoaPods, or from the
// process image when hidapi is linked statically (Swift Package Manager).
//
// Referencing the hidapi functions here keeps the objects that define them in
// the final binary, since nothing else in this package calls them at link time.
void *u2f_hidapi_symbols[] = {
    (void *)hid_init,
    (void *)hid_exit,
    (void *)hid_enumerate,
    (void *)hid_free_enumeration,
    (void *)hid_open,
    (void *)hid_open_path,
    (void *)hid_write,
    (void *)hid_read,
    (void *)hid_read_timeout,
    (void *)hid_set_nonblocking,
    (void *)hid_send_feature_report,
    (void *)hid_get_feature_report,
    (void *)hid_close,
    (void *)hid_get_manufacturer_string,
    (void *)hid_get_product_string,
    (void *)hid_get_serial_number_string,
    (void *)hid_get_indexed_string,
    (void *)hid_error,
};
