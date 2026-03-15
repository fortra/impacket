# Fix #2099: Handle truncated SMB responses (SessionError + debug log)

## Reported problem

When SMB authentication runs against a host that drops the connection, times out, or sends a truncated session setup response, the client can hit:

```
ValueError: subsection not found
```

The traceback points at `structure.py` (`data.index(b'\x00')` for asciiz) and then through `smb.login_extended` → `sessionData.fromString(sessionResponse['Data'])`. The message is unclear and the error is never turned into an authentication/connection failure, so callers see a raw `ValueError` instead of a session error. ([Issue #2099](https://github.com/fortra/impacket/issues/2099); see also [PR #2118](https://github.com/fortra/impacket/pull/2118) and maintainer feedback there.)

---

## How we fixed it

1. **Structure layer (`impacket/structure.py`)**  
   For asciiz (`'z'`) parsing, we catch the `ValueError` from `data.index(b'\x00')` and re-raise with a clear message that includes the field name, e.g. *"Can't find NUL terminator in field 'NativeOS'"*. We also pass the field name through the code specifier so formats like `'z=""'` get the correct name in the message.

2. **SMB layer (`impacket/smb.py`)**  
   We handle parsing failures at every place that parses session/negotiate responses:
   - **Session setup (two call sites):** `sessionData.fromString(sessionResponse['Data'])` is wrapped in `try`/`except ValueError`. On failure we log the exception at **debug** and raise **`SessionError`** with `STATUS_LOGON_FAILURE` so the failure is reported as an authentication error.
   - **Negotiate path (two call sites):** The same pattern is used for `_dialects_data.fromString(...)` and the extended-security parse; we log at debug and raise **`SessionError`** with `STATUS_INVALID_PARAMETER` so the failure is reported as a connection/response error.

   Callers (including `smbconnection.login()`) now receive a normal **SessionError** (with a clear code and message) instead of a raw **ValueError**.

3. **Documentation**  
   The `smbconnection.login()` docstring is updated to mention that a session error can be raised for invalid or truncated server response. An implementation plan (`IMPLEMENTATION_PLAN_2099.md`) and a ChangeLog entry document the change.

---

## Regression testing

- **Structure layer**  
  In `tests/misc/test_structure.py`, **`Test_asciiz_no_nul_raises_clear_error`**:
  - Asserts that unpacking a structure with an asciiz field from data that has **no NUL** raises **`ValueError`** whose message includes the field name and “NUL terminator” (so we never again surface the generic “subsection not found” for this case).
  - Covers both a simple asciiz field and a session-like structure (length-prefixed blob + asciiz, similar to SMB `NativeOS`).

- **SMB layer**  
  In `tests/SMB_RPC/test_smb.py`, **`Test_Issue2099_SessionError_On_Truncated_Response::test_login_raises_session_error_when_session_response_parsing_fails`**:
  - Mocks the transport so that the server “sends” a minimal negotiate response and then a minimal session-setup response.
  - Patches **`SMBSessionSetupAndX_Extended_Response_Data.fromString`** to raise **`ValueError`** (simulating a truncated/malformed response).
  - Asserts that either **`SMBConnection(...)`** or **`conn.login(...)`** raises a **SessionError** (or the underlying `smb.SessionError`) with an error code set, so we never again let a **ValueError** from this parsing path escape to the caller.

Together, these tests ensure that (1) the structure layer gives a clear **ValueError** when a NUL is missing, and (2) the SMB layer turns that into a **SessionError** so the bug does not reappear.

---

## Checklist

- [x] Structure layer raises a descriptive `ValueError` for asciiz without NUL.
- [x] SMB layer catches `ValueError` at all four parse sites, logs at debug, and raises `SessionError`.
- [x] Regression tests added and passing (structure + SMB).
- [x] Lint (flake8) and non-remote test run pass; wheel builds.

Fixes #2099.
