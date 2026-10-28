FROM python:3.12-alpine AS build

WORKDIR /src
RUN pip install --no-cache-dir "markdown>=3.5"
COPY README.md CONTRIBUTING.md CHANGELOG.md ./
COPY docs/build.py docs/template.html docs/style.css docs/
RUN python docs/build.py --out /site

FROM nginx:1.27-alpine

COPY docs/nginx-container.conf /etc/nginx/conf.d/default.conf
COPY --from=build /site /usr/share/nginx/html
EXPOSE 8080
