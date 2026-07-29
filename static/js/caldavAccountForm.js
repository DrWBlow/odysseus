// Pure CalDAV form helpers.  Keeping request construction separate from the
// browser DOM makes the credential-preservation contract directly testable.

export function buildCalDavTestRequest({
  authType,
  accountId = '',
  url = '',
  username = '',
  password = '',
}) {
  if (authType === 'oauth2_google' && !accountId) {
    return { ok: false, error: 'Save and connect first' };
  }
  if (authType === 'basic') {
    return {
      ok: true,
      body: {
        url,
        username,
        password,
        ...(accountId ? { account_id: accountId } : {}),
      },
    };
  }
  return { ok: true, body: accountId ? { account_id: accountId } : {} };
}

export function resolveGoogleAccountId(saved, isNew, editId) {
  const accountId = isNew ? saved?.id : editId;
  if (!accountId) {
    return { ok: false, error: 'Save succeeded but account ID was missing' };
  }
  return { ok: true, accountId };
}

export function defaultCalDavUrl(authType, draftUrl, savedUrl) {
  if (draftUrl !== undefined) return draftUrl;
  if (savedUrl) return savedUrl;
  return authType === 'oauth2_google'
    ? 'https://apidata.googleusercontent.com/caldav/v2/'
    : '';
}
