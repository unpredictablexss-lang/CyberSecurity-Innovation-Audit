"""AUTH-02, CWE-862: missing server-side authorization.

A reviewed entry reaches a modeled sensitive operation without a matched guard
on the original caller. A client-side check or a check on another operation does
not establish server-side authorization for this path.
"""

FAMILY = "AUTH-02"
TITLE = "missing server-side authorization"
CWE = "CWE-862"
RULES = ("ipc.auth.missing",)

from ..models import ServiceAccountRole

# This is deliberately a repository- and operation-scoped exception, not a
# globally trusted UID. In security_access_token, PrivacyManagerStub compares
# the IPC caller UID with ACCESSTOKEN_UID=3020 and the method's rejecting
# condition explicitly allows this service account OR PERMISSION_USED_STATS.
# The component's pinned privacy.cfg assigns privacy_service to user "access_token";
# OpenHarmony startup_init_lite maps that account to 3020.
POLICY = {
    "repository_service_account_roles": (
        ServiceAccountRole(
            "ACCESSTOKEN_UID", "3020", "<caller-account:access-token-service>",
            ("RemovePermissionUsedRecords",),
            "security_access_token: privacy_manager_stub.h defines ACCESSTOKEN_UID=3020; "
            "privacy_manager_stub.cpp compares GetCallingUid() to it and "
            "RemovePermissionUsedRecordsInner explicitly allows this service role or "
            "PERMISSION_USED_STATS; privacy.cfg sets privacy_service uid=access_token. "
            "External binding: openharmony/startup_init_lite@"
            "c0a40a20207db69495691920f8650df8e634c7f8 services/etc/passwd:30 maps "
            "access_token to 3020. Reviewed for this single operation only.",
            repository="openharmony/security_access_token",
        ),
    ),
    # OpenHarmony multimedia_camera_framework!4873 adds CheckSystemApp as the
    # first guard in this exact method on OpenHarmony-5.1.0-Release. This
    # repository-scoped contract ties that gate to session creation.
    "repository_caller_class_contracts": (
        ("openharmony/multimedia_camera_framework",
         "HCameraService::CreateDeferredVideoProcessingSession",
         "system_app", ("CreateDeferredVideoProcessingSession",)),
    ),
}
