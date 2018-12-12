all: setup proto run

setup:
	python3 -m venv venv
	source ./venv/bin/activate ; pip install -r requirements.txt

proto:
	protoc --python_out=./ *.proto

run:
	docker-compose up -d
ifeq ("$(wildcard public.key)","")
	openssl genrsa -out private.key 4096
	openssl rsa -in private.key -outform PEM -pubout -out public.key
endif
	source ./venv/bin/activate ; REDIS_HOST=localhost python server.py

stop:
	docker-compose down