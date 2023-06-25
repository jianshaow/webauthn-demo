# webauthn-demo

##
~~~ shell
export image_ver=0.0.1
npm run build
docker build -t jianshao/webauthn-demo:$image_ver .
docker push jianshao/webauthn-demo:$image_ver
docker run -d --name webauthn-demo --rm jianshao/webauthn-demo:$image_ver
~~~
