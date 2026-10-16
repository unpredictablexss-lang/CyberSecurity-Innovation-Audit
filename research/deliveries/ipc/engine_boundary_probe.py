"""One difference at a time at the boundaries of the entry and caller-role mechanisms.

Read-only. Two batteries, each candidate the same program with exactly one thing
changed, so a difference between two lines of output is attributable to that one thing.

**Battery A -- one-hop dispatch resolution.** A stub whose dispatch handler calls an
unqualified virtual method, and a subclass overriding it:

  a_literal_credited / a_literal_ungated   literal class name, gated / ungated
  a_by_value_pointer_return_credited       the implementer returns the object by value
  b_macro_stub_credited                    the class named `Stub`, `#define Stub <x>`
  c_macro_other_name_credited              the class named `OnehopStub` under a macro
  d_literal_not_unique / e_macro_stub_...  two implementers, literal vs macro

**Battery B -- a reviewed caller-role name that the sources also define.** The same
entry, whose call site is a member of the entry's own class in both, differing only in
how the name it calls is defined: as a member of that class, or as a file-scope function.

Measured on `oh-ipc-2026.10-v7` (worktree `work/ipc-20261017`); the readings and where
each is asserted are in `20261017-engine-case-coverage-six-families.md` §4-§6. Note for
anyone editing this file: an earlier version of battery B spliced the member definition
into the class body and produced invalid C++ -- the run then reported `blocked` and
`Local caller-role definition is unresolved`, which is a reaction to a source the parser
could not take, not a statement about shadowing. Both texts are written out literally
here for that reason.

    python research/deliveries/ipc/engine_boundary_probe.py            # both batteries
    python research/deliveries/ipc/engine_boundary_probe.py b_         # filter by name
"""
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from src.parser.ast import parse_source  # noqa: E402
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit  # noqa: E402
from src.ohscanner.fixture import snapshot_digest  # noqa: E402
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector  # noqa: E402

HEAD = '#include "common_types.h"\n'
TYPEDEF = 'typedef RemoteObject *RemoteObjectPtr;\n\n'
GATE = 'if (!IsSACalling()) return -1;\n'

BODY = '''class %STUB% {
public:
int OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option);
int HandleGetObject(MessageParcel &data,MessageParcel &reply);
virtual int GetObject(int32_t id,RemoteObjectPtr &object);
};

class FixtureOnehopService : public %STUB% {
public:
int GetObject(int32_t id,RemoteObjectPtr &object) override;
};

int %STUB%::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
if (code == 1) return HandleGetObject(data,reply);
return 0;
}

int %STUB%::HandleGetObject(MessageParcel &data,MessageParcel &reply) {
int32_t id = data.ReadInt32();
RemoteObjectPtr object;
GetObject(id,object);
reply.WriteRemoteObject(object);
return 0;
}

int FixtureOnehopService::GetObject(int32_t id,RemoteObjectPtr &object) {
%GATE%object = PrivilegedObject();
return 0;
}
'''

# The same program with the object coming back as a pointer return value instead of
# through a reference out-parameter. The export is written from the returned value.
BODY_POINTER_RETURN = '''class %STUB% {
public:
int OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option);
int HandleGetObject(MessageParcel &data,MessageParcel &reply);
virtual RemoteObjectPtr GetObject(int32_t id);
};

class FixtureOnehopService : public %STUB% {
public:
RemoteObjectPtr GetObject(int32_t id) override;
};

int %STUB%::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
if (code == 1) return HandleGetObject(data,reply);
return 0;
}

int %STUB%::HandleGetObject(MessageParcel &data,MessageParcel &reply) {
int32_t id = data.ReadInt32();
RemoteObjectPtr object = GetObject(id);
reply.WriteRemoteObject(object);
return 0;
}

RemoteObjectPtr FixtureOnehopService::GetObject(int32_t id) {
%GATE%return PrivilegedObject();
}
'''

SECOND_IMPLEMENTER = '''class FixtureOnehopServiceB : public %STUB% {
public:
int GetObject(int32_t id,RemoteObjectPtr &object) override;
};

int FixtureOnehopServiceB::GetObject(int32_t id,RemoteObjectPtr &object) {
%GATE%object = PrivilegedObject();
return 0;
}
'''

# Battery B: the same entry, calling a reviewed caller-role name that the scanned
# source also defines. The call site is a member of the entry's own class in both, so
# the one difference is how the name it calls is defined: as a member of that class,
# or as a file-scope function.
MEMBER_PREDICATE = '''#define Stub Fixture_member_predicate
#include "common_types.h"

constexpr int SERVICE_UID = 4096;

class Stub {
public:
int OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option);
bool IsAccessTokenCalling() const;
};

bool Stub::IsAccessTokenCalling() const {
int callingUid = IPCSkeleton::GetCallingUid();
return callingUid == SERVICE_UID;
}

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
if (!IsAccessTokenCalling()) return -1;
DeleteUserData(IPCSkeleton::GetCallingUid());
return 0;
}
'''

FREE_PREDICATE = '''#define Stub Fixture_free_predicate
#include "common_types.h"

constexpr int SERVICE_UID = 4096;

bool IsAccessTokenCalling() {
int callingUid = IPCSkeleton::GetCallingUid();
return callingUid == SERVICE_UID;
}

class Stub {
public:
int OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option);
};

int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option) {
if (data.ReadInterfaceToken() != GetDescriptor()) return -1;
if (!IsAccessTokenCalling()) return -1;
DeleteUserData(IPCSkeleton::GetCallingUid());
return 0;
}
'''


def program(stub, gate, macro=None, second_implementer=False, template=BODY,
            extra_lines=0):
    text = template.replace('%STUB%', stub).replace('%GATE%', gate)
    if second_implementer:
        text += '\n' + SECOND_IMPLEMENTER.replace('%STUB%', stub).replace('%GATE%', gate)
    return (('#define %s Fixture_%s\n' % (macro, macro) if macro else '')
            + HEAD + TYPEDEF + text)


CANDIDATES = {
    'a_literal_credited': program('FixtureOnehopCreditedStub', GATE),
    'a_literal_ungated': program('FixtureOnehopUngatedStub', ''),
    'a_by_value_pointer_return_credited': program('FixtureOnehopPtrStub', GATE,
                                                  template=BODY_POINTER_RETURN),
    'b_macro_stub_credited': program('Stub', GATE, macro='Stub'),
    'c_macro_other_name_credited': program('OnehopStub', GATE, macro='OnehopStub'),
    'd_literal_not_unique': program('FixtureOnehopNotUniqueStub', GATE,
                                    second_implementer=True),
    'e_macro_stub_not_unique': program('Stub', GATE, macro='Stub',
                                       second_implementer=True),
    'b_member_predicate': MEMBER_PREDICATE,
    'b_free_predicate': FREE_PREDICATE,
}

TOKENS = ('one-hop', 'hop ', 'cross-tu', 'not unique', 'dispatch handler',
          'stays a candidate', 'caller-role definition', 'is also defined')


def context(text, path):
    index = parse_source(text, language='cpp')
    unit = SourceUnit(path, 'cpp', text, hashlib.sha256(text.encode()).hexdigest(),
                      index.parse_status)
    request = ScanRequest('ipc-probe', 'fixture/ipc', 'synthetic-ipc-v1',
                          snapshot_digest((unit,)), 'current-component:fixture/ipc')
    return ScanContext(request, (unit,), {'ast': {path: index.to_dict()}})


def main(argv):
    for name in sorted(CANDIDATES):
        if argv and not any(token in name for token in argv):
            continue
        ctx = context(CANDIDATES[name], name + '.cpp')
        run = IpcInterfaceDetector().detect(ctx, ctx.units)
        print('=' * 78)
        print(name, '| status:', run.status, '| rules:',
              sorted((f.rule_id, f.line) for f in run.findings))
        for limit in run.limitations:
            if any(token in limit.lower() for token in TOKENS):
                print('   L:', limit[:240])
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
