package com.fabi.galaxymirror
import android.content.Context
import android.os.Build
import android.security.keystore.*
import java.io.*
import java.nio.ByteBuffer
import java.security.*
import java.security.spec.*
import javax.crypto.*
import javax.crypto.spec.*

object SecureChannel {
 private const val PREFS="gm_secure"; private const val WRAP_ALIAS="GalaxyMirrorPairingWrapV2"; private const val ID_ALIAS="GalaxyMirrorIdentityP256V2"
 private const val ITERATIONS=310000; private const val TAG_BITS=128; private const val NONCE_BYTES=12; private const val SALT_BYTES=16; private const val MAX_KEY=1024; private const val HASH=32
 data class Packet(val type:Int,val flags:Int,val pts:Long,val payload:ByteArray)
 fun hasPairing(c:Context)=c.getSharedPreferences(PREFS,0).contains("blob")
 fun createPairingCode():String=ByteArray(24).also{SecureRandom().nextBytes(it)}.let{android.util.Base64.encodeToString(it,android.util.Base64.NO_WRAP or android.util.Base64.URL_SAFE)}
 fun enroll(c:Context,code:String){require(code.length>=24);val salt=ByteArray(SALT_BYTES).also{SecureRandom().nextBytes(it)};val spec=PBEKeySpec(code.toCharArray(),salt,ITERATIONS,256);val raw=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded;spec.clearPassword();val n=ByteArray(NONCE_BYTES).also{SecureRandom().nextBytes(it)};val x=Cipher.getInstance("AES/GCM/NoPadding");x.init(Cipher.ENCRYPT_MODE,wrapKey(),GCMParameterSpec(TAG_BITS,n));val blob=x.doFinal(raw);raw.fill(0);c.getSharedPreferences(PREFS,0).edit().putString("salt",b64(salt)).putString("nonce",b64(n)).putString("blob",b64(blob)).remove("peer").apply();identity()}
 fun senderHandshake(c:Context,i:DataInputStream,o:DataOutputStream)=handshake(c,i,o,true)
 fun receiverHandshake(c:Context,i:DataInputStream,o:DataOutputStream)=handshake(c,i,o,false)
 private fun handshake(c:Context,i:DataInputStream,o:DataOutputStream,sender:Boolean):Session{
  val pair=pairingBytes(c);val id=identity();val eph=KeyPairGenerator.getInstance("EC").apply{initialize(ECGenParameterSpec("secp256r1"),SecureRandom())}.generateKeyPair();val nonce=ByteArray(32).also{SecureRandom().nextBytes(it)};val myId=id.public.encoded;val myE=eph.public.encoded
  try{val peer=if(sender){writeHello(o,myId,myE,nonce);readHello(i)}else{val p=readHello(i);writeHello(o,myId,myE,nonce);p};validateEcPublic(peer.id);validateEcPublic(peer.eph)
   val transcript=if(sender)concat(myId,myE,nonce,peer.id,peer.eph,peer.nonce)else concat(peer.id,peer.eph,peer.nonce,myId,myE,nonce)
   val proof=hmacRaw(pair,"GMV5-pair-proof".toByteArray(),transcript)
   if(sender){o.write(proof);writeBytes(o,sign(id.private,transcript));o.flush();verifyPeer(i,pair,peer.id,transcript)}else{verifyPeer(i,pair,peer.id,transcript);o.write(proof);writeBytes(o,sign(id.private,transcript));o.flush()}
   verifyPinned(c,peer.id);val peerE=KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(peer.eph));val ka=KeyAgreement.getInstance("ECDH");ka.init(eph.private);ka.doPhase(peerE,true);val shared=ka.generateSecret();val th=sha256(transcript);val ikm=concat(shared,pair,th);val salt=sha256("GalaxyMirror-GMV5-HKDF-Salt".toByteArray(),th);val prk=hkdfExtract(salt,ikm);shared.fill(0);ikm.fill(0);val okm=hkdfExpand(prk,"GalaxyMirror-GMV5-session".toByteArray(),104);prk.fill(0)
   val s2r=okm.copyOfRange(0,32);val r2s=okm.copyOfRange(32,64);val sp=okm.copyOfRange(64,68);val rp=okm.copyOfRange(68,72);val confirm=okm.copyOfRange(72,104);okm.fill(0)
   val mine=hmacRaw(confirm,(if(sender)"sender-confirm" else "receiver-confirm").toByteArray(),th);val expected=hmacRaw(confirm,(if(sender)"receiver-confirm" else "sender-confirm").toByteArray(),th)
   if(sender){o.write(mine);o.flush();val got=ByteArray(HASH);i.readFully(got);require(MessageDigest.isEqual(got,expected));got.fill(0)}else{val got=ByteArray(HASH);i.readFully(got);require(MessageDigest.isEqual(got,expected));got.fill(0);o.write(mine);o.flush()}
   mine.fill(0);expected.fill(0);confirm.fill(0);commitPin(c,peer.id)
   return if(sender)Session(SecretKeySpec(s2r,"AES"),SecretKeySpec(r2s,"AES"),sp,rp)else Session(SecretKeySpec(r2s,"AES"),SecretKeySpec(s2r,"AES"),rp,sp)
  }finally{pair.fill(0);nonce.fill(0)}
 }
 private data class Hello(val id:ByteArray,val eph:ByteArray,val nonce:ByteArray)
 private fun writeHello(o:DataOutputStream,id:ByteArray,e:ByteArray,n:ByteArray){o.writeInt(MirrorProtocol.MAGIC);o.writeInt(MirrorProtocol.VERSION);writeBytes(o,id);writeBytes(o,e);writeBytes(o,n);o.flush()}
 private fun readHello(i:DataInputStream):Hello{require(i.readInt()==MirrorProtocol.MAGIC);val v=i.readInt();require(v==MirrorProtocol.VERSION&&v>=MirrorProtocol.MIN_SECURE_VERSION);return Hello(readBytes(i,MAX_KEY),readBytes(i,MAX_KEY),readBytes(i,64).also{require(it.size==32)})}
 private fun verifyPeer(i:DataInputStream,pair:ByteArray,id:ByteArray,t:ByteArray){val p=ByteArray(HASH);i.readFully(p);val e=hmacRaw(pair,"GMV5-pair-proof".toByteArray(),t);require(MessageDigest.isEqual(p,e));p.fill(0);e.fill(0);val sig=readBytes(i,256);val pub=KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(id));require(verify(pub,t,sig));sig.fill(0)}
 private fun verifyPinned(c:Context,p:ByteArray){val old=c.getSharedPreferences(PREFS,0).getString("peer",null)?:return;val now=sha256(p);require(MessageDigest.isEqual(unb64(old),now));now.fill(0)}
 private fun commitPin(c:Context,p:ByteArray){val sp=c.getSharedPreferences(PREFS,0);if(sp.getString("peer",null)==null)sp.edit().putString("peer",b64(sha256(p))).commit()}
 private fun validateEcPublic(e:ByteArray){require(KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(e)).algorithm.equals("EC",true))}
 private fun identity():KeyPair{val ks=KeyStore.getInstance("AndroidKeyStore").apply{load(null)};if(ks.containsAlias(ID_ALIAS))return KeyPair(ks.getCertificate(ID_ALIAS).publicKey,ks.getKey(ID_ALIAS,null) as PrivateKey);fun gen(strong:Boolean):KeyPair{val b=KeyGenParameterSpec.Builder(ID_ALIAS,KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY).setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1")).setDigests(KeyProperties.DIGEST_SHA256);if(Build.VERSION.SDK_INT>=28)b.setIsStrongBoxBacked(strong);return KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC,"AndroidKeyStore").apply{initialize(b.build())}.generateKeyPair()};return try{gen(true)}catch(_:Exception){gen(false)}}
 private fun wrapKey():SecretKey{val ks=KeyStore.getInstance("AndroidKeyStore").apply{load(null)};(ks.getKey(WRAP_ALIAS,null) as? SecretKey)?.let{return it};fun gen(strong:Boolean):SecretKey{val b=KeyGenParameterSpec.Builder(WRAP_ALIAS,KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setKeySize(256);if(Build.VERSION.SDK_INT>=28)b.setIsStrongBoxBacked(strong);return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore").apply{init(b.build())}.generateKey()};return try{gen(true)}catch(_:Exception){gen(false)}}
 private fun pairingBytes(c:Context):ByteArray{val p=c.getSharedPreferences(PREFS,0);val n=unb64(p.getString("nonce",null)?:error("Not paired"));val b=unb64(p.getString("blob",null)?:error("Not paired"));return Cipher.getInstance("AES/GCM/NoPadding").run{init(Cipher.DECRYPT_MODE,wrapKey(),GCMParameterSpec(TAG_BITS,n));doFinal(b)}}
 class Session(private val tx:SecretKey,private val rx:SecretKey,private val tp:ByteArray,private val rp:ByteArray):AutoCloseable{private var sc=0L;private var rc=-1L;private var closed=false
  @Synchronized fun write(o:DataOutputStream,p:Packet){check(!closed);require(p.payload.size<=MirrorProtocol.MAX_PACKET);val c=sc++;val x=Cipher.getInstance("AES/GCM/NoPadding");x.init(Cipher.ENCRYPT_MODE,tx,GCMParameterSpec(TAG_BITS,nonce(tp,c)));x.updateAAD(aad(c,p.type,p.flags,p.pts));val e=x.doFinal(p.payload);o.writeLong(c);o.writeInt(p.type);o.writeInt(p.flags);o.writeLong(p.pts);o.writeInt(e.size);o.write(e);o.flush()}
  @Synchronized fun read(i:DataInputStream):Packet{check(!closed);val c=i.readLong();if(c<=rc)throw SecurityException("Replay");val t=i.readInt();val f=i.readInt();val pts=i.readLong();val z=i.readInt();if(z<16||z>MirrorProtocol.MAX_PACKET+16)throw SecurityException("Bad packet");val e=ByteArray(z);i.readFully(e);val x=Cipher.getInstance("AES/GCM/NoPadding");x.init(Cipher.DECRYPT_MODE,rx,GCMParameterSpec(TAG_BITS,nonce(rp,c)));x.updateAAD(aad(c,t,f,pts));val p=x.doFinal(e);e.fill(0);rc=c;return Packet(t,f,pts,p)}
  override fun close(){closed=true;tp.fill(0);rp.fill(0)}
  private fun nonce(p:ByteArray,c:Long)=ByteBuffer.allocate(12).put(p).putLong(c).array();private fun aad(c:Long,t:Int,f:Int,p:Long)=ByteBuffer.allocate(28).putInt(MirrorProtocol.VERSION).putLong(c).putInt(t).putInt(f).putLong(p).array()}
 private fun hkdfExtract(s:ByteArray,i:ByteArray)=hmacRaw(s,i)
 private fun hkdfExpand(p:ByteArray,info:ByteArray,len:Int):ByteArray{val out=ByteArray(len);var t=ByteArray(0);var pos=0;var ctr=1;while(pos<len){val n=hmacRaw(p,t,info,byteArrayOf(ctr++.toByte()));t.fill(0);t=n;val z=minOf(t.size,len-pos);System.arraycopy(t,0,out,pos,z);pos+=z};t.fill(0);return out}
 private fun hmacRaw(k:ByteArray,vararg x:ByteArray)=Mac.getInstance("HmacSHA256").run{init(SecretKeySpec(k,"HmacSHA256"));x.forEach{update(it)};doFinal()}
 private fun sha256(vararg x:ByteArray)=MessageDigest.getInstance("SHA-256").run{x.forEach{update(it)};digest()}
 private fun concat(vararg x:ByteArray)=ByteArray(x.sumOf{it.size}).also{r->var p=0;x.forEach{System.arraycopy(it,0,r,p,it.size);p+=it.size}}
 private fun sign(k:PrivateKey,d:ByteArray)=Signature.getInstance("SHA256withECDSA").run{initSign(k);update(d);sign()}
 private fun verify(k:PublicKey,d:ByteArray,s:ByteArray)=Signature.getInstance("SHA256withECDSA").run{initVerify(k);update(d);verify(s)}
 private fun writeBytes(o:DataOutputStream,b:ByteArray){o.writeInt(b.size);o.write(b)}
 private fun readBytes(i:DataInputStream,m:Int)=ByteArray(i.readInt().also{require(it in 1..m)}).also{i.readFully(it)}
 private fun b64(v:ByteArray)=android.util.Base64.encodeToString(v,android.util.Base64.NO_WRAP)
 private fun unb64(v:String)=android.util.Base64.decode(v,android.util.Base64.NO_WRAP)
}