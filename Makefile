SHELL	= /bin/sh

NAME	= transcendence

ifeq ($(wildcard srcs/.env), srcs/.env)
    include srcs/.env
		export
endif

all: certs create_volumes_dirs
	cd srcs && docker compose up --build

check_certs: # creates certificates if needed
	@if [ ! -d "volumes/certs" ] || [ ! -f "volumes/certs/cert.pem" ] || \
		[ ! -f "volumes/certs/key.pem" ]; then \
		$(MAKE) certs; \
	fi

create_volumes_dirs: # creates volume directories if needed
	mkdir -p ./volumes/frontend ./volumes/backend ./volumes/certs ./volumes/logs

down:
	cd srcs && docker compose down -v
stop:
	cd srcs && docker compose stop

prune:
	docker image prune
routine:
	docker system prune -a
reset:
	docker stop $$(docker ps -qa); \
	docker rm $$(docker ps -qa); \
	docker rmi -f $$(docker images -qa); \
	docker volume rm $$(docker volume ls -q); \
	docker network rm $$(docker network ls -q) 2>/dev/null

certs:
	mkdir -p volumes/certs && cd volumes/certs && openssl req -x509 -nodes \
		-newkey rsa:4096 -days 365 \
		-keyout temp_key.pem -out cert.pem \
		-subj "/C=ES/L=Malaga/O=42 Malaga/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,DNS:gateway,DNS:authentif,\
		DNS:profileapi,DNS:play,DNS:calcgame,DNS:nginx" && \
	install -m 644 temp_key.pem key.pem && rm temp_key.pem

postgres:
	docker exec -it postgres sh \
		-c "psql -U postgres_main_user -d my_db"
deletenotifications:
	docker exec postgres sh \
		-c "psql -U postgres_main_user -d my_db -c 'DELETE FROM profileapi_notification;'"
deletefriendships:
	docker exec postgres sh \
		-c "psql -U postgres_main_user -d my_db -c 'DELETE FROM profileapi_profile_friends;'"
deletemessages:
	docker exec postgres sh \
		-c "psql -U postgres_main_user -d my_db -c 'DELETE FROM livechat_message;'"

gateway_restart:
	docker restart gateway

MAKEMESSAGES_CMD	= "\
    python manage.py makemessages -l en && \
    python manage.py makemessages -l fr && \
    python manage.py makemessages -l es"

COMPILEMESSAGES_CMD	= "python manage.py compilemessages"

makemessages:
	docker exec authentif sh -c $(MAKEMESSAGES_CMD)
	docker exec calcgame sh -c $(MAKEMESSAGES_CMD)
	docker exec gateway sh -c $(MAKEMESSAGES_CMD)
	docker exec play sh -c $(MAKEMESSAGES_CMD)
	docker exec profileapi sh -c $(MAKEMESSAGES_CMD)

compilemessages:
	docker exec authentif sh -c $(COMPILEMESSAGES_CMD)
	docker exec calcgame sh -c $(COMPILEMESSAGES_CMD)
	docker exec gateway sh -c $(COMPILEMESSAGES_CMD)
	docker exec play sh -c $(COMPILEMESSAGES_CMD)
	docker exec profileapi sh -c $(COMPILEMESSAGES_CMD)

.phony: all down stop logs prune routine reset certs postgres \
	gateway_restart postgres \
	deletenotifications deletefriendships deletefriendships \
	makemessages compilemessages

