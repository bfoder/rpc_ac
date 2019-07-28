import rpc_ac

DOMAIN = 'PROVIDE VALUE'
API_KEY = 'PROVIDE VALUE'
SECRET_KEY = 'PROVIDE VALUE'

eu_pulscms = rpc_ac.ApiClient(DOMAIN, API_KEY, SECRET_KEY)
print(eu_pulscms.story.search())
