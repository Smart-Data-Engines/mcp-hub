# Using the MCP Hub console

Open `/admin/` and continue with your company sign-in. Accounts appear in the
console after their first sign-in. The console uses your workspace's configured
identity provider.

## Give one person access to a server

As an administrator:

1. Open **MCP servers** and choose the server.
2. In **Access**, choose the person by their name or email.
3. Choose **Add personal permissions**, select what they may do, and **Save access**.

**Read** permits search and viewing. **Create & update** permits write tools.
**Delete & destructive** permits tools classified as destructive. These are
separate permissions: select Read too if a person needs to read and write.

The preview shows the permissions that will apply, including the person's group.
When necessary, saving also shares the server with this particular person. It does
not change its audience to the whole organization. An old deny is removed when
personal permissions are saved.

**Use group permissions** clears personal rules and follows the person's group.
**Block access** clears personal grants and blocks access inherited from their
group. Administrators and the server owner retain full access through their role
or ownership; personal rules cannot restrict them.

Changes apply to the next tool request. An AI client may cache its tool list:
refresh that list, reconnect, or use `hub.discover_tools` to see current tools.
A stopped server must be started before its tools are usable.

Managers can change regular users' access but cannot change their own or an
administrator's access. An administrator must first share a restricted server
with the target person; a manager cannot change another owner's server audience.

## Give a team the same permissions

1. Open **Groups → Create group** and name the group.
2. Check its servers and choose their permissions using the form.
3. **Save group**.
4. Open **Users & access**, choose a person, select the **Permission group**, and
   **Save group assignment**.

Each person belongs to one group. Personal permissions add capabilities to the
group's permissions; they do not reduce group capabilities. The user view explains
the effective result for each server.

A private or selected-people audience can still restrict group members. The group
form identifies these servers and links to their Access page. Share each person,
or explicitly choose **Advanced · server audience → Organization** to make the
server eligible for group-based access. Organization audience still requires
permissions; it does not grant tool access to every account.

New people join `default`. Deleting a custom group returns its human members to
`default` and its service clients to `_bots`; their personal rules remain.

## Connect your AI client

**Overview** shows the MCP endpoint and a **Copy endpoint** button. Add that remote
endpoint in your client's MCP settings, sign in with the same company account, and
allow access. The catalog displays the tools permitted to this account.

The built-in discovery tool is labelled **Hub utility**; tool counts in the
workspace statistics describe upstream tools.

## Save your personal credentials

Open **My credentials**, choose an MCP server, and fill the fields declared by
that server. The form loads the latest permissions, including recently granted
access. **Show entered values** only reveals what you have just typed; saved
secrets are never loaded back into the form.

New values replace that server's saved personal credential object. Fill all
required fields. Leave fields empty when changing only your preference.
**Use only my credentials** prevents fallback to a shared connection and makes
calls fail while your credentials are missing. Removing credentials retains this
preference; the removal dialog explains the result.

An advanced JSON input remains available for adapters with custom credential
objects. It is not required for declared personal fields. Shared server credentials
are configured by administrators in the server's **Connection** tab.

## Configure a server connection

Open **MCP servers → server → Connection**. Each declared server environment field
has a regular input and a **Saved** or **Not set** status. Saved values stay hidden;
enter a new value to replace one, or leave it blank to keep the existing value.
**Remove saved value** explicitly marks a field for removal and can be undone before
saving. **Save connection** changes only the edited fields.

Changes apply when the server starts. A running server shows **Restart to apply**
while it still uses the previous values. The connection-mode summary explains
whether people use a shared connection, their own credentials or a shared fallback.
Administrators can change this under **Change connection mode**.

## Find and update server code

The **Source** tab shows the Git repository, folder, branch or pinned reference and
running code version. Open the repository, publish the source changes there and
restart the server to deploy them. A pinned reference must be updated in Settings
before deploying a new reference.

**Browse source files** is optional. Writable registries also offer **Edit source
in console**; saving commits the changed files together. If the enhanced editor
cannot load, the basic text editor still supports editing and saving. No editor
installation is required. With a read-only registry identity, publish changes
through Git and use the console to deploy them.

## Navigation and editing

Sections, selected servers and selected users have bookmarkable URLs. Refreshing
or using the browser Back button preserves the selected page. Company sign-in
returns to the requested section. On small screens, use **Menu**; sign-out remains
available next to your account.

Forms warn before leaving unsaved edits. Confirmation dialogs support Escape,
Tab and Shift+Tab. Failed saves retain the draft and show a retryable error.
Server source files are committed together; start or restart applies saved code.
