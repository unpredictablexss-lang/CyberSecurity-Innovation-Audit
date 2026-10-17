// Differential harness for MessageParcelWarp::ReadRawData
// (openharmony/distributeddatamgr_pasteboard, vulnerable 3287e854 vs fixed
// ddee7c00).
//
// One binary per revision; both are built from the component's unchanged
// message_parcel_warp.cpp at the revision recorded in the manifest, over the
// real c_utils Parcel. See README.md for what is real and what is supplied.
//
// Scenarios are chosen so that the only difference between the two revisions
// is the one line the fix adds:
//
//   A  non-ashmem descriptor, declared size <= file size
//      vulnerable: returns a mapping of the file; the caller reads file bytes
//      fixed:      nullptr (AshmemGetSize < 0)
//   B  non-ashmem descriptor, declared size > file size
//      vulnerable: returns a mapping longer than the file; reading past EOF
//                  raises SIGBUS in the caller (observed in a forked child)
//      fixed:      nullptr (the AshmemGetSize check)
//   C  small payload (<= MIN_RAW_SIZE): ReadUnpadBuffer, no descriptor
//      both revisions: same bytes, no descriptor involved
//   D  declared size disagrees with the parcel's own ReadInt64
//      both revisions: nullptr, the pre-existing check
//
// The harness prints one JSON object per scenario on stdout.

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "message_parcel_warp.h"

using OHOS::MessageParcel;
using OHOS::MiscServices::MessageParcelWarp;

namespace {

constexpr size_t kSmallPayload = 1024;
constexpr size_t kLargeSize = 64 * 1024;      // > MIN_RAW_SIZE (32 KiB)
constexpr size_t kShortFileSize = 4096;

void json_string(const char *key, const std::string &value, bool last = false)
{
    std::printf("\"%s\": \"%s\"%s", key, value.c_str(), last ? "" : ", ");
}

void json_number(const char *key, long long value, bool last = false)
{
    std::printf("\"%s\": %lld%s", key, value, last ? "" : ", ");
}

int make_file(size_t size, unsigned char fill, std::string *path)
{
    char name[] = "/tmp/parcel-harness-XXXXXX";
    int fd = mkstemp(name);
    if (fd < 0) {
        return -1;
    }
    *path = name;
    if (ftruncate(fd, static_cast<off_t>(size)) != 0) {
        close(fd);
        return -1;
    }
    std::string buffer(size, static_cast<char>(fill));
    ssize_t written = pwrite(fd, buffer.data(), size, 0);
    if (written != static_cast<ssize_t>(size)) {
        close(fd);
        return -1;
    }
    return fd;
}

// Scenario A: a descriptor that is not ashmem, whose file is large enough for
// the declared size. The vulnerable revision maps it and hands the content
// back as if it were pasteboard raw data.
void scenario_non_ashmem_fits(const char *revision)
{
    std::string path;
    int fd = make_file(kLargeSize, 'A', &path);
    if (fd < 0) {
        std::printf("{\"scenario\": \"A_non_ashmem_fits\", \"error\": \"setup\"}\n");
        return;
    }
    MessageParcel parcel;
    parcel.WriteInt64(static_cast<int64_t>(kLargeSize));
    parcel.WriteFileDescriptor(fd);

    MessageParcelWarp warp;
    const void *data = warp.ReadRawData(parcel, kLargeSize);

    std::printf("{");
    json_string("scenario", "A_non_ashmem_fits");
    json_string("revision", revision);
    json_string("result", data == nullptr ? "null" : "non_null");
    json_number("declared_size", static_cast<long long>(kLargeSize));
    json_number("file_size", static_cast<long long>(kLargeSize));
    if (data != nullptr) {
        const unsigned char *bytes = static_cast<const unsigned char *>(data);
        json_number("first_byte", bytes[0]);
        json_number("last_byte", bytes[kLargeSize - 1]);
    } else {
        json_string("first_byte", "n/a");
        json_string("last_byte", "n/a");
    }
    // The mapping lives in `warp`; read before it is destroyed.
    json_string("kind", "non_ashmem_file", true);
    std::printf("}\n");

    close(fd);
    unlink(path.c_str());
}

// Scenario B: the declared size is larger than the file behind the descriptor.
// The vulnerable revision still returns a mapping; the caller's read past EOF
// raises SIGBUS. The touch runs in a child so the parent can report the signal.
void scenario_non_ashmem_short(const char *revision)
{
    std::string path;
    int fd = make_file(kShortFileSize, 'B', &path);
    if (fd < 0) {
        std::printf("{\"scenario\": \"B_non_ashmem_short\", \"error\": \"setup\"}\n");
        return;
    }
    MessageParcel parcel;
    parcel.WriteInt64(static_cast<int64_t>(kLargeSize));
    parcel.WriteFileDescriptor(fd);

    MessageParcelWarp warp;
    const void *data = warp.ReadRawData(parcel, kLargeSize);

    std::string touch = "not_attempted";
    int term_signal = 0;
    if (data != nullptr) {
        pid_t child = fork();
        if (child == 0) {
            volatile unsigned char byte =
                static_cast<const unsigned char *>(data)[kLargeSize - 1];
            (void)byte;
            _exit(0);
        }
        int status = 0;
        waitpid(child, &status, 0);
        if (WIFSIGNALED(status)) {
            touch = "signalled";
            term_signal = WTERMSIG(status);
        } else if (WIFEXITED(status)) {
            touch = status == 0 ? "survived" : "exited";
        }
    }

    std::printf("{");
    json_string("scenario", "B_non_ashmem_short");
    json_string("revision", revision);
    json_string("result", data == nullptr ? "null" : "non_null");
    json_number("declared_size", static_cast<long long>(kLargeSize));
    json_number("file_size", static_cast<long long>(kShortFileSize));
    json_string("read_past_eof", touch);
    json_number("signal", term_signal, true);
    std::printf("}\n");

    close(fd);
    unlink(path.c_str());
}

// Scenario C: the unchanged small-payload path. Both revisions must still
// return the bytes; the differential above is about the descriptor path only.
void scenario_small_payload(const char *revision)
{
    std::string payload(kSmallPayload, 'C');
    MessageParcel parcel;
    parcel.WriteInt64(static_cast<int64_t>(kSmallPayload));
    parcel.WriteUnpadBuffer(payload.data(), kSmallPayload);

    MessageParcelWarp warp;
    const void *data = warp.ReadRawData(parcel, kSmallPayload);

    std::printf("{");
    json_string("scenario", "C_small_payload");
    json_string("revision", revision);
    json_string("result", data == nullptr ? "null" : "non_null");
    json_number("declared_size", static_cast<long long>(kSmallPayload));
    if (data != nullptr) {
        json_string("bytes_match", std::memcmp(data, payload.data(), kSmallPayload) == 0 ? "yes" : "no");
    } else {
        json_string("bytes_match", "n/a");
    }
    json_string("kind", "unpad_buffer", true);
    std::printf("}\n");
}

// Scenario D: the pre-existing declared-size check. Both revisions reject.
void scenario_size_mismatch(const char *revision)
{
    std::string path;
    int fd = make_file(kLargeSize, 'D', &path);
    if (fd < 0) {
        std::printf("{\"scenario\": \"D_size_mismatch\", \"error\": \"setup\"}\n");
        return;
    }
    MessageParcel parcel;
    parcel.WriteInt64(static_cast<int64_t>(kLargeSize + 1));
    parcel.WriteFileDescriptor(fd);

    MessageParcelWarp warp;
    const void *data = warp.ReadRawData(parcel, kLargeSize);

    std::printf("{");
    json_string("scenario", "D_size_mismatch");
    json_string("revision", revision);
    json_string("result", data == nullptr ? "null" : "non_null");
    json_number("declared_size", static_cast<long long>(kLargeSize));
    json_number("parcel_int64", static_cast<long long>(kLargeSize + 1), true);
    std::printf("}\n");

    close(fd);
    unlink(path.c_str());
}

} // namespace

int main(int argc, char **argv)
{
    const char *revision = argc > 1 ? argv[1] : "unrecorded";
    scenario_non_ashmem_fits(revision);
    scenario_non_ashmem_short(revision);
    scenario_small_payload(revision);
    scenario_size_mismatch(revision);
    return 0;
}
