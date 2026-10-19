"""New owned service units keep process output out of the node journal."""
import pytest

pytestmark = pytest.mark.unit_portable


@pytest.mark.parametrize('kind',['persistent','oneshot'])
def test_new_owned_units_do_not_persist_process_output(kind):
    from plan_executor.executor import oneshot_service, persistent_service
    class Remote:
        def __init__(self):self.commands=[]
        def run(self,command,**kwargs):self.commands.append(command)
    remote=Remote()
    if kind=='persistent':persistent_service(remote,'owned-qa','exec true')
    else:oneshot_service(remote,'owned-qa','true','true')
    unit=remote.commands[-1]
    assert 'StandardOutput=null\n' in unit
    assert 'StandardError=null\n' in unit
    assert 'UMask=0077\n' in unit
