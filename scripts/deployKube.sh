#!/bin/bash

#Install and configure ingress
#echo "    "
#echo "    "
echo "Installing and configuring Ingress"
#/bin/bash deployIngress.sh

#Install cert-manager
echo "    "
echo "    "
echo "Installing cert-manager"
/bin/bash deployCertManager.sh

/bin/bash initNamespaces.sh

kubectl -n mango apply -f ../kube/root-tls-cert-issuer.yaml
kubectl -n mango wait --timeout=30s --for=condition=Ready issuer/root-tls-cert-issuer

# Use the self-signing issuer to generate the org Issuers, one for each org.
kubectl -n mango apply -f ../kube/mango-tls-cert-issuer.yaml
kubectl -n mango wait --timeout=30s --for=condition=Ready issuer/mango-tls-cert-issuer

kubectl apply -f ../kube/apple-path.yaml  -n apple
kubectl apply -f ../kube/apple-host.yaml  -n apple
kubectl apply -f ../kube/banana-path.yaml -n banana
kubectl apply -f ../kube/banana-host.yaml -n banana

kubectl create -f ../kube/mango.yaml -n mango

echo "Waiting for all components to be up"
sleep 30

#Build pekko http server app docker images
echo "    "
echo "    "
echo "Build docker image and put into minikube image repo"
/bin/bash buildDockerImage.sh

echo "      "
echo "      "
echo "Creating papaya server secret"
kubectl apply -f ../kube/papaya-auth.yaml -n papaya

echo "      "
echo "      "
echo "Creating papaya server persistent volume claim"
kubectl apply -f ../kube/papaya-pvc.yaml -n papaya

echo "      "
echo "      "
echo "Deploying root-tls-cert-issuer"
kubectl -n papaya apply -f ../kube/root-tls-cert-issuer.yaml
kubectl -n papaya wait --timeout=30s --for=condition=Ready issuer/root-tls-cert-issuer

echo "      "
echo "      "
echo "Deploying tls_server-tls-cert-issuer"
kubectl -n papaya apply -f ../kube/papaya-tls-cert-issuer.yaml
kubectl -n papaya wait --timeout=30s --for=condition=Ready issuer/papaya-tls-cert-issuer

echo "      "
echo "      "
echo "Deploying tls_server deployment, service and ingress"
kubectl apply -f ../kube/papaya.yaml -n papaya

echo "      "
echo "      "
echo "Deploying passion deployment, service and ingress"
kubectl apply -f ../kube/passionfruit.yaml -n passion

ipAddr=$(minikube ip)
echo "Minikube ip = $ipAddr"
sudo -- sh -c 'echo "\n'"$ipAddr"' passion.foo.com apple.foo.com banana.foo.com mango.foo.com papaya.foo.com\n" >> /etc/hosts'

#echo "Invoking apple"
#curl -kL http://$ipAddr/apple

#echo "Invoking banana"
#curl -kL http://$ipAddr/banana

#echo "Invoking a not found"
#curl -kL http://$ipAddr/notfound

#curl -kL http://apple.foo.com/apple
#curl -kL http://banana.foo.com/banana

