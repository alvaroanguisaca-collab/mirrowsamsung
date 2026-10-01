package com.fabi.galaxymirror
import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.*
class MainActivity:Activity(){
 override fun onCreate(state:Bundle?){super.onCreate(state);val root=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL;setPadding(48,48,48,48)}
 root.addView(TextView(this).apply{text="Galaxy Mirror";textSize=30f})
 root.addView(TextView(this).apply{text="Espejo local S22 Ultra → Galaxy Tab";textSize=17f})
 root.addView(Button(this).apply{text="S22 ULTRA — ENVIAR PANTALLA";setOnClickListener{startActivity(Intent(this@MainActivity,SenderActivity::class.java))}})
 root.addView(Button(this).apply{text="GALAXY TAB — RECIBIR EN HORIZONTAL";setOnClickListener{startActivity(Intent(this@MainActivity,ReceiverActivity::class.java))}})
 setContentView(root)}
}