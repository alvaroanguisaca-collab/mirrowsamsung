package com.fabi.galaxymirror
import android.app.*
import android.content.*
import android.media.projection.MediaProjectionManager
import android.os.Bundle
import android.widget.*
import java.util.concurrent.Executors
class SenderActivity:Activity(){
 private lateinit var pm:MediaProjectionManager;private lateinit var status:TextView;private lateinit var start:Button;private lateinit var pairing:EditText;private var ip:String?=null;private val ex=Executors.newSingleThreadExecutor()
 override fun onCreate(s:Bundle?){super.onCreate(s);pm=getSystemService(MediaProjectionManager::class.java);val r=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL;setPadding(48,48,48,48)};status=TextView(this);pairing=EditText(this).apply{hint="Código de emparejamiento";isSingleLine=true};start=Button(this).apply{text="BUSCAR TABLET"};r.addView(status);if(!SecureChannel.hasPairing(this))r.addView(pairing);r.addView(start);setContentView(r);start.setOnClickListener{discover()};discover()}
 private fun discover(){start.isEnabled=false;status.text="Buscando Galaxy Tab…";ex.execute{val found=NetworkDiscovery.findReceiver();runOnUiThread{ip=found;if(found==null){status.text="Tablet no encontrada";start.text="VOLVER A BUSCAR";start.isEnabled=true;start.setOnClickListener{discover()}}else{status.text="Tablet encontrada";start.text="AUTORIZAR Y TRANSMITIR";start.isEnabled=true;start.setOnClickListener{request()}}}}}
 private fun request(){if(!SecureChannel.hasPairing(this)){val c=pairing.text.toString().trim();if(c.length<24){status.text="Código incompleto";return};SecureChannel.enroll(this,c)};startActivityForResult(pm.createScreenCaptureIntent(),700)}
 @Deprecated("MediaProjection result") override fun onActivityResult(r:Int,c:Int,d:Intent?){super.onActivityResult(r,c,d);if(r==700&&c==RESULT_OK&&d!=null&&ip!=null){startForegroundService(Intent(this,ProjectionService::class.java).putExtra(ProjectionService.EXTRA_RESULT_CODE,c).putExtra(ProjectionService.EXTRA_RESULT_DATA,d).putExtra(ProjectionService.EXTRA_RECEIVER_IP,ip));status.text="Transmitiendo";start.isEnabled=false}}
 override fun onDestroy(){ex.shutdownNow();super.onDestroy()}
}