import collections

meta_fields = 'email hostname username checked'.split()
mx_fields = 'has_mx mx_record mx_amount bad_lookup lookup_exception'.split()
is_fields = 'is_valid is_email is_free is_common'.split()
trust_fields = 'is_trusted trust_rating'.split()
config_fields = 'enable_mx_lookup trust_cut_off'.split()

MetaData = collections.namedtuple('MetaData', meta_fields)
MxData = collections.namedtuple('MxData', mx_fields)
IsData = collections.namedtuple('IsData', is_fields)
TrustData = collections.namedtuple('TrustData', trust_fields)
ConfigData = collections.namedtuple('ConfigData', config_fields)

Data = collections.namedtuple('Data', meta_fields + mx_fields + is_fields + trust_fields + config_fields)
