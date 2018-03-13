# API Management
This is Flask based micro service. 

####Building
```bash
docker build -t api-authentication:0.0.0 .
```
####Deploy
``` kubectl apply -f deployment.yaml```
####Service
```kubectl apply -f service.yaml```


##Releases
1.0.0 - initial release
1.0.1 - Release 1.0.1
1.0.2 - This release is not to be used. It experienced some build/release issues and required a new release to be done.
1.0.3 - The second release auth.


routing_key='fctn.services.mgmt.config.<service>'
msg = { 'to': 'orguserroles', 
        'category': 'config',
        'property': 'loglevel',
        'value': 'debug'}