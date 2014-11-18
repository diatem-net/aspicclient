<?php

include 'aspicclient/aspicclient.php';

//Commentaire
AspicClient::init('172.31.6.52/aspicserver/', 'kapoue', '123', false);


if(isset($_GET['login'])){
    AspicClient::login();
}

if(isset($_GET['logout'])){
    AspicClient::logout();
}

echo '<b>is authentified : </b>';
$authentified = AspicClient::isAuthentified();

if($authentified){
    echo '<h1>Vous êtes authentifié</h1>';
    echo '<br>';
    echo 'Bonjour '.AspicClient::getUserId();
    echo '<br>';
    echo 'UserData : ';
    echo '<br>';
    var_dump(AspicClient::getUserData());
    echo '<br>';
    echo '<br>';
    echo '<a href="?logout">LOGOUT</a>';
}else{
    echo '<h1>Vous n\'êtes pas authentifié</h1>';
    echo '<br>';
    echo '<a href="?login">LOGIN</a>';
}