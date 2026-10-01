package com.fabi.galaxymirror
import android.app.*
import android.content.pm.ActivityInfo
import android.media.*
import android.os.*
import android.view.*
import android.widget.*
import java.io.*
import java.net.*
import java.util.concurrent.atomic.AtomicBoolean
class ReceiverActivity:Activity(),SurfaceHolder.Callback{
 private val running=AtomicBoolean(true);private lateinit var surface:SurfaceView;private lateinit var status:TextView;private var server:Thread?=null;private var offers:Thread?=null
 override fun onCreate(s:Bundle?){super.onCreate(s);requestedOrientation=ActivityInfo.SCREEN_ORIENTATION_SENSOR_LANDSCAPE;window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);val f=FrameLayout(this);surface=SurfaceView(this).also{it.holder.addCallback(this);f.addView(it)};status=TextView(this).apply{textSize=22f;gravity=Gravity.CENTER};f.addView(status,FrameLayout.LayoutParams(-1,-1));setContentView(f);if(!SecureChannel.hasPairing(this)){val code=SecureChannel.createPairingCode();SecureChannel.enroll(this,code);status.text="Código de emparejamiento:\n$code"}else status.text="Esperando S22 Ultra…";offers=Thread{NetworkDiscovery.serveOffers(running)}.apply{start()}}
 override fun surfaceCreated(h:SurfaceHolder){if(server?.isAlive==true)return;server=Thread{ServerSocket(MirrorProtocol.VIDEO_PORT).use{ss->ss.soTimeout=1000;while(running.get()){try{receive(ss.accept(),h.surface)}catch(_:SocketTimeoutException){}catch(_:Exception){runOnUiThread{status.visibility=View.VISIBLE;status.text="Esperando reconexión…"}}}}}.apply{start()}}
 private fun receive(s:Socket,out:Surface){s.use{val i=DataInputStream(BufferedInputStream(s.getInputStream()));val o=DataOutputStream(BufferedOutputStream(s.getOutputStream()));require(i.readInt()==MirrorProtocol.MAGIC);require(i.readInt()==MirrorProtocol.VERSION);val w=i.readInt();val h=i.readInt();i.readInt();SecureChannel.receiverHandshake(this,i,o).use{sec->val fmt=MediaFormat.createVideoFormat(MediaFormat.MIMETYPE_VIDEO_AVC,w,h);val d=MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_VIDEO_AVC);d.configure(fmt,out,null,0);d.start();runOnUiThread{status.visibility=View.GONE};try{while(running.get()){val p=sec.read(i);require(p.type==MirrorProtocol.TYPE_FRAME||p.type==MirrorProtocol.TYPE_CODEC_CONFIG);var n=d.dequeueInputBuffer(10000);if(n>=0){d.getInputBuffer(n)?.apply{clear();put(p.payload)};d.queueInputBuffer(n,0,p.payload.size,p.pts,p.flags)};while(true){val bi=MediaCodec.BufferInfo();val q=d.dequeueOutputBuffer(bi,0);if(q>=0)d.releaseOutputBuffer(q,true)else break}}}finally{try{d.stop();d.release()}catch(_:Exception){}}}}}
 override fun surfaceChanged(h:SurfaceHolder,f:Int,w:Int,x:Int){};override fun surfaceDestroyed(h:SurfaceHolder){}
 override fun onDestroy(){running.set(false);server?.interrupt();offers?.interrupt();super.onDestroy()}
}