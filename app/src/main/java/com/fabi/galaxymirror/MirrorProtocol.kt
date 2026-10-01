package com.fabi.galaxymirror
object MirrorProtocol {
 const val DISCOVERY_PORT=49876; const val VIDEO_PORT=49877
 const val DISCOVER="GALAXY_MIRROR_DISCOVER_V3"; const val OFFER="GALAXY_MIRROR_OFFER_V3"
 const val MAGIC=0x474D5635; const val VERSION=5; const val MIN_SECURE_VERSION=5
 const val TYPE_CODEC_CONFIG=1; const val TYPE_FRAME=2; const val TYPE_HEARTBEAT=3
 const val MAX_PACKET=4*1024*1024; const val CONNECT_TIMEOUT_MS=4000; const val SOCKET_TIMEOUT_MS=8000
}