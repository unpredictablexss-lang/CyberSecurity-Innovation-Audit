#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <string>

namespace {

constexpr uint32_t kGetRenderSession = 190;
constexpr const char* kDescriptor = "ohos.window.IScreenSessionManager";

enum class CallerKind {
    kUnprivilegedApp,
    kSystemApp,
    kNativeService,
};

struct RemoteObject {
    std::string id;
};

struct MessageParcel {
    std::string descriptor;
    uint32_t code = 0;
    uint64_t screenId = 0;
    RemoteObject* reply = nullptr;
    bool wroteRemoteObject = false;
};

class ScreenSession {
public:
    explicit ScreenSession(std::shared_ptr<RemoteObject> renderSession)
        : renderSession_(std::move(renderSession)) {}

    std::shared_ptr<RemoteObject> GetRenderSession() const
    {
        return renderSession_;
    }

private:
    std::shared_ptr<RemoteObject> renderSession_;
};

class ScreenSessionManager {
public:
    ScreenSessionManager()
    {
        sessions_.emplace(7, std::make_shared<ScreenSession>(
            std::make_shared<RemoteObject>(RemoteObject{"render-session:7"})));
    }

    std::shared_ptr<RemoteObject> GetRenderSession(uint64_t screenId) const
    {
        const auto it = sessions_.find(screenId);
        if (it == sessions_.end()) {
            return nullptr;
        }
        return it->second->GetRenderSession();
    }

private:
    std::map<uint64_t, std::shared_ptr<ScreenSession>> sessions_;
};

bool IsSystemCalling(CallerKind caller)
{
    return caller == CallerKind::kSystemApp || caller == CallerKind::kNativeService;
}

bool FixedControlAllows(CallerKind caller)
{
    return caller == CallerKind::kSystemApp || caller == CallerKind::kNativeService;
}

int32_t OnRemoteRequestInner(CallerKind caller, MessageParcel& data, MessageParcel& reply,
    ScreenSessionManager& manager)
{
    switch (data.code) {
        case kGetRenderSession: {
#if defined(CAP01_VARIANT_FIXED_CONTROL)
            if (!FixedControlAllows(caller)) {
                break;
            }
#elif defined(CAP01_VARIANT_PATCHED)
            if (!IsSystemCalling(caller)) {
                break;
            }
#elif !defined(CAP01_VARIANT_VULNERABLE)
#error "Define exactly one CAP01_VARIANT_* macro"
#endif
            auto renderSession = manager.GetRenderSession(data.screenId);
            reply.reply = renderSession.get();
            reply.wroteRemoteObject = renderSession != nullptr;
            break;
        }
        default:
            return -1;
    }
    return 0;
}

int32_t OnRemoteRequest(CallerKind caller, MessageParcel& data, MessageParcel& reply,
    ScreenSessionManager& manager)
{
    if (data.descriptor != kDescriptor) {
        return -1;
    }
    return OnRemoteRequestInner(caller, data, reply, manager);
}

std::string JsonBool(bool value)
{
    return value ? "true" : "false";
}

}  // namespace

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cerr << "usage: cap01_render_session_export <scenario>\n";
        return 2;
    }

    const std::string scenario = argv[1];
    CallerKind caller = CallerKind::kUnprivilegedApp;
    std::string descriptor = kDescriptor;
    uint64_t screenId = 7;

    if (scenario == "unauthorized_export") {
        caller = CallerKind::kUnprivilegedApp;
    } else if (scenario == "authorized_export") {
        caller = CallerKind::kSystemApp;
    } else if (scenario == "wrong_descriptor") {
        caller = CallerKind::kUnprivilegedApp;
        descriptor = "wrong.interface.Descriptor";
    } else if (scenario == "unknown_screen") {
        caller = CallerKind::kSystemApp;
        screenId = 999;
    } else {
        std::cerr << "unknown scenario: " << scenario << "\n";
        return 2;
    }

    ScreenSessionManager manager;
    MessageParcel data{descriptor, kGetRenderSession, screenId, nullptr, false};
    MessageParcel reply;
    const int32_t status = OnRemoteRequest(caller, data, reply, manager);

    std::cout << "{\"scenario\":\"" << scenario << "\""
              << ",\"status\":" << status
              << ",\"exported\":" << JsonBool(reply.wroteRemoteObject)
              << ",\"object_id\":\"" << (reply.reply ? reply.reply->id : "") << "\""
              << ",\"model_only\":true}\n";
    return 0;
}
