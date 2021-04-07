from prometheus_client import Counter
from prometheus_client import start_http_server

c = Counter('my_failures', 'Description of counter')
c.inc()     # Increment by 1
c.inc(1.6)  # Increment by given value

start_http_server(5000)

while True:
    pass
