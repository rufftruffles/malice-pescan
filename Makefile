REPO=malice-plugins/pescan
ORG=malice
NAME=pescan
CATEGORY=exe
VERSION?=$(shell cat VERSION)
MALWARE=tests/hw2.exe


all: build size tag test

.PHONY: build
build:
	docker build -t $(ORG)/$(NAME):$(VERSION) .

.PHONY: size
size:
	sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell docker images --format "{{.Size}}" $(ORG)/$(NAME):$(VERSION)| cut -d' ' -f1)-blue/' README.md

.PHONY: tag
tag:
	docker tag $(ORG)/$(NAME):$(VERSION) $(ORG)/$(NAME):latest

.PHONY: tags
tags:
	docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" $(ORG)/$(NAME)

.PHONY: ssh
ssh:
	@docker run --init -it --rm --entrypoint=bash $(ORG)/$(NAME):$(VERSION)

.PHONY: tar
tar:
	docker save $(ORG)/$(NAME):$(VERSION) -o $(NAME).tar

.PHONY: go-test
go-test:
	go get
	go test -v

.PHONY: start_elasticsearch
start_elasticsearch:
ifeq ("$(shell docker inspect -f {{.State.Running}} elasticsearch)", "true")
	@echo "===> elasticsearch already running.  Stopping now..."
	@docker rm -f elasticsearch || true
endif
	@echo "===> Starting elasticsearch"
	@docker run --init -d --name elasticsearch -p 9200:9200 blacktop/elasticsearch:6
	@wait-for-es

.PHONY: test_all
test_all: test test_elastic test_markdown

.PHONY: test
test:
	@echo "===> ${NAME} --help"
	docker run --init --rm $(ORG)/$(NAME):$(VERSION) --help
	docker run --init --rm -v $(PWD):/malware $(ORG)/$(NAME):$(VERSION) -V $(MALWARE) | jq . > docs/results.json
	cat docs/results.json | jq .

.PHONY: test_elastic
test_elastic: start_elasticsearch
	@echo "===> ${NAME} test_elastic"
	docker run --rm --link elasticsearch -e MALICE_ELASTICSEARCH_URL=http://elasticsearch:9200 -v $(PWD):/malware $(ORG)/$(NAME):$(VERSION) -V $(MALWARE)
	http localhost:9200/malice/_search | jq . > docs/elastic.json

.PHONY: test_extern_elastic
test_extern_elastic:
	@echo "===> ${NAME} test_extern_elastic"
	docker run --rm -it \
	-e MALICE_ELASTICSEARCH_URL=${MALICE_ELASTICSEARCH_URL} \
	-e MALICE_ELASTICSEARCH_USERNAME=${MALICE_ELASTICSEARCH_USERNAME} \
	-e MALICE_ELASTICSEARCH_PASSWORD=${MALICE_ELASTICSEARCH_PASSWORD} \
	-e MALICE_ELASTICSEARCH_INDEX="test" \
	-v $(PWD):/malware $(ORG)/$(NAME):$(VERSION) -V $(MALWARE)

.PHONY: test_markdown
test_markdown: test_elastic
	@echo "===> ${NAME} test_markdown"
	cat docs/elastic.json | jq -r '.hits.hits[] ._source.plugins.${CATEGORY}.${NAME}.markdown' > docs/SAMPLE.md

.PHONY: stop
stop: ## Kill running docker containers
	@docker rm -f $(NAME) || true

.PHONY: circle
circle: ci-size
	@sed -i.bu 's/docker%20image-.*-blue/docker%20image-$(shell cat .circleci/size)-blue/' README.md
	@echo "===> Image size is: $(shell cat .circleci/size)"

ci-build:
	@echo "===> Getting CircleCI build number"
	@http https://circleci.com/api/v1.1/project/github/${REPO} | jq '.[0].build_num' > .circleci/build_num

ci-size: ci-build
	@echo "===> Getting artifact sizes from CircleCI"
	@cd .circleci; rm size || true
	@http https://circleci.com/api/v1.1/project/github/${REPO}/$(shell cat .circleci/build_num)/artifacts${CIRCLE_TOKEN} | jq -r ".[] | .url" | xargs wget -q -P .circleci

clean:
	docker-clean stop
	docker image rm $(ORG)/$(NAME):$(VERSION)
	docker image rm $(ORG)/$(NAME):latest
	rm $(MALWARE)

# Absolutely awesome: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s %s\n", $$1, $$2}'

.DEFAULT_GOAL := all
