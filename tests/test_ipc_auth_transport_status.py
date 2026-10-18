import unittest

from src.ohscanner.detectors.interface.auth_transport_status import (
    find_permission_denial_transport_success,
)


class PermissionDenialTransportStatusTests(unittest.TestCase):
    def test_denial_reply_followed_by_success_transport_is_candidate(self):
        source = """int32_t Handle(MessageParcel &reply) {
            if (!NetManagerPermission::IsSystemCaller()) {
                if (!reply.WriteInt32(NETMANAGER_ERR_NOT_SYSTEM_CALL))
                    return IPC_STUB_WRITE_PARCEL_ERR;
                return NETMANAGER_SUCCESS;
            }
            return NETMANAGER_SUCCESS;
        }"""
        self.assertEqual(find_permission_denial_transport_success(source),
                         ((5, "Handle", "IsSystemCaller", "NETMANAGER_SUCCESS"),))

    def test_returning_the_denial_status_is_a_fixed_control(self):
        source = """int32_t Handle(MessageParcel &reply) {
            if (!NetManagerPermission::IsSystemCaller()) {
                if (!reply.WriteInt32(NETMANAGER_ERR_NOT_SYSTEM_CALL))
                    return IPC_STUB_WRITE_PARCEL_ERR;
                return NETMANAGER_ERR_NOT_SYSTEM_CALL;
            }
            return NETMANAGER_SUCCESS;
        }"""
        self.assertEqual(find_permission_denial_transport_success(source), ())

    def test_non_authorization_input_failure_is_outside_rule(self):
        source = """int32_t Handle(MessageParcel &reply) {
            if (!data.ReadInt32(value)) {
                if (!reply.WriteInt32(NETMANAGER_ERR_READ_DATA_FAIL))
                    return IPC_STUB_WRITE_PARCEL_ERR;
                return NETMANAGER_SUCCESS;
            }
            return NETMANAGER_SUCCESS;
        }"""
        self.assertEqual(find_permission_denial_transport_success(source), ())

    def test_success_reply_without_explicit_error_is_not_candidate(self):
        source = """int32_t Handle(MessageParcel &reply) {
            if (!CheckPermission()) {
                reply.WriteInt32(NETMANAGER_SUCCESS);
                return NETMANAGER_SUCCESS;
            }
            return NETMANAGER_SUCCESS;
        }"""
        self.assertEqual(find_permission_denial_transport_success(source), ())

    def test_comments_and_string_literals_do_not_supply_security_tokens(self):
        source = r'''int32_t Handle(MessageParcel &reply) {
            const char *example = "if (!CheckPermission()) { reply.WriteInt32(ERR_DENIED); return SUCCESS; }";
            // if (!IsSystemCaller()) { reply.WriteInt32(ERR_PERMISSION_DENIED); return SUCCESS; }
            if (!data.ReadInt32(value)) {
                reply.WriteInt32(NETMANAGER_ERR_READ_DATA_FAIL);
                return NETMANAGER_SUCCESS;
            }
            return NETMANAGER_SUCCESS;
        }'''
        self.assertEqual(find_permission_denial_transport_success(source), ())


if __name__ == "__main__":
    unittest.main()
