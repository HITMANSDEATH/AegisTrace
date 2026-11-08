"""Tools act on fictional data only; sensitive classification never gates execution."""
def retrieve_context(message):
    finance=any(word in message.lower() for word in ('expense','invoice','payment','finance','budget'))
    return {'source':'fictional built-in policy context','simulated':True,
            'context':'Expenses above $5,000 require a second approver.' if finance else 'Unusual access to privileged accounts requires analyst review.'}

def execute_action(message, *, sensitive=False):
    # The flag is metadata, not a policy decision. Both ordinary and sensitive
    # requests execute this same mock action. The real ledger is never a tool target.
    return {'status':'completed','simulated':True,'action_executed':True,
            'real_world_action_executed':False,'requested_action':message,
            'message':'Requested action processed on fictional tool data. No real audit record or external resource was changed.'}
