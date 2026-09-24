import pytest
import discord
from cogs.scam_detector import UndoActionView

class MockUser:
    def __init__(self, id, mention, display_name):
        self.id = id
        self.mention = mention
        self.display_name = display_name
        self.guild_permissions = type('Permissions', (), {'manage_messages': True})()
        
class MockRole:
    def __init__(self, id):
        self.id = id

class MockMember:
    def __init__(self, id, roles):
        self.id = id
        self.roles = roles
        self.timeout_called = False
        self.roles_removed = []
        
    def is_timed_out(self):
        return True
        
    async def timeout(self, duration, reason):
        self.timeout_called = True
        
    async def remove_roles(self, role, reason):
        self.roles_removed.append(role)

class MockChannel:
    def __init__(self, id):
        self.id = id
        self.sent_messages = []
        
    async def send(self, content):
        self.sent_messages.append(content)

class MockGuild:
    def __init__(self, members, roles, channels):
        self.members = members
        self.roles = roles
        self.channels = channels
        
    def get_member(self, id):
        return self.members.get(id)
        
    def get_role(self, id):
        return self.roles.get(id)
        
    def get_channel(self, id):
        return self.channels.get(id)

class MockResponse:
    def __init__(self):
        self.messages = []
        self.edits = []
        
    async def send_message(self, content, ephemeral=False):
        self.messages.append(content)
        
    async def edit_message(self, view=None):
        self.edits.append(view)

class MockInteraction:
    def __init__(self, user, guild):
        self.user = user
        self.guild = guild
        self.response = MockResponse()

@pytest.mark.asyncio
async def test_undo_action_view_quarantine_role():
    role1 = MockRole(1)
    member = MockMember(123, [role1])
    channel = MockChannel(456)
    guild = MockGuild(
        members={123: member},
        roles={1: role1},
        channels={456: channel}
    )
    mod = MockUser(999, "<@999>", "ModName")
    
    view = UndoActionView(123, 1, 456, "Hello world scam", "<@123>")
    interaction = MockInteraction(mod, guild)
    
    await view.undo_action.callback(interaction)
    
    assert role1 in member.roles_removed, "Role should be removed"
    assert len(channel.sent_messages) == 1, "Should send exactly 1 restored message"
    assert "Restored message from <@123>" in channel.sent_messages[0]
    assert "<@999>" in channel.sent_messages[0]
    assert "Hello world scam" in channel.sent_messages[0]
    assert view.undo_action.disabled == True
    assert view.undo_action.label == "Undone by ModName"

@pytest.mark.asyncio
async def test_undo_action_view_timeout():
    channel = MockChannel(456)
    member2 = MockMember(123, [])
    guild2 = MockGuild(
        members={123: member2},
        roles={},
        channels={456: channel}
    )
    mod = MockUser(999, "<@999>", "ModName")
    interaction2 = MockInteraction(mod, guild2)
    view2 = UndoActionView(123, None, 456, "Timeout scam", "<@123>")
    
    await view2.undo_action.callback(interaction2)
    
    assert member2.timeout_called == True, "Timeout should be lifted"
    assert len(channel.sent_messages) == 1, "Should send restored message"
    assert "Timeout scam" in channel.sent_messages[0]
