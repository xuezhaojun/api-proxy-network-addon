Setup a test env based on kind by these steps(consider anp images are all ready generated):
* run `make docker-build/user-server docker-build/kubectl-proxy`
* run `./gen-clusters.sh` 
* run `./apply-certs.sh`
* run `./load-images-kind.sh`
* run `./apply-resources.sh`