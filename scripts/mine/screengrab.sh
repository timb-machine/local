#!/bin/sh
URL="$1"
filename="`echo $URL | tr ":\/?&=" "-"`"
rekonq "$URL" &
sleep 1
qdbus org.kde.rekonq /rekonq/MainWindow_1 org.qtproject.Qt.QWidget.showMaximized
ksnapshot &
pid="`pgrep ksnapshot`"
sleep 1
qdbus "org.kde.ksnapshot-$pid" /KSnapshot org.kde.ksnapshot.save "file://$HOME/$filename.png"
