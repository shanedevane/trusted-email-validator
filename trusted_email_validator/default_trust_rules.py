import collections

TRUST_RULES = list()
TrustRule = collections.namedtuple('TrustRule', 'regex attribute reason')


def trust_rule(rule_function):
    rule = rule_function()
    TRUST_RULES.append(rule)
    return rule


@trust_rule
def trust_rule_mx_amount():
    return TrustRule(r'^1$', 'mx_amount', 'only 1 mail server reported')


@trust_rule
def trust_rule_numbers_username():
    return TrustRule(r'.*?[0-9]+.*?', 'username', 'numbers in username')


@trust_rule
def trust_rule_mixed_case():
    return TrustRule(r'.*?[A-Z]+[a-z]+.*?', 'username', 'mixed case in username')


# @trust_rule
# def trust_rule_username_small():
#     return TrustRule(r'.*?[A-Z]+[a-z]+.*?', len(self.username), 'username is really small')


@trust_rule
def trust_rule_only_upper_case():
    return TrustRule(r"^[A-Z-0-9\'_]+$", 'username', 'only upper case in username')


@trust_rule
def trust_rule_only_upper_case():
    return TrustRule(r"^True$", 'is_free', 'email is from a free provider')


@trust_rule
def trust_rule_non_letter():
    return TrustRule(r"^[^A-Za-z]+", 'username', 'non letter at start')



