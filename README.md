# webauthn-demo

##
~~~ shell
npm install
# start locally
npm run start
# build
npm run build
# install serve
npm install -g serve
# run with serve
serve -s build
# build and run with docker
export image_ver=0.1.2
docker build -t jianshao/webauthn-demo:$image_ver .
docker push jianshao/webauthn-demo:$image_ver
docker run -d --name webauthn-demo --rm -p 80:80 jianshao/webauthn-demo:$image_ver
docker stop webauthn-demo
~~~
