# 由于github上部署的私有有密码
# 需要额外配置Circle-CI，填入私钥指纹
# 曲线救国，在issue中找到方法，需要pip安装ghp-import

echo '----mkdocs build----'
mkdocs build
#echo '----复制谷歌搜索验证网页----'
#cp google88663f3caf9ed787.html ./site/google88663f3caf9ed787.html
echo '----ghp-import site----'
ghp-import site
echo '----上传到origin gh-pages----'
git push -f origin gh-pages