# webauthn-demo

##
~~~ shell
npm install
npm run build
export image_ver=0.0.1
docker build -t jianshao/webauthn-demo:$image_ver .
docker push jianshao/webauthn-demo:$image_ver
docker run -d --name webauthn-demo --rm -p 80:80 jianshao/webauthn-demo:$image_ver
docker stop webauthn-demo
~~~
