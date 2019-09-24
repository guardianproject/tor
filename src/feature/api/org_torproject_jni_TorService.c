/* Copyright (c) 2019, Matthew Finkel.
 * Copyright (c) 2019, Hans-Christoph Steiner.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "tor_api.h"
#include "org_torproject_jni_TorService.h"
#include "orconfig.h"
#include "lib/malloc/malloc.h"

#include <jni.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_SYS_UN_H
#include <sys/socket.h>
#include <sys/un.h>
#endif

#ifdef __ANDROID__
#include <android/log.h>
#define fprintf(ignored, ...)                                           \
  __android_log_print(ANDROID_LOG_ERROR, "Tor-api", ##__VA_ARGS__)
#endif // __ANDROID__

/* with JNI, unused parameters are inevitable, suppress the warnings */
#define UNUSED(x) (void)(x)

static char **argv = NULL;
static int argc = 0;

static jfieldID
GetConfigurationFieldID(JNIEnv *env, jclass torApiClass)
{
  return (*env)->GetFieldID(env, torApiClass, "torConfiguration", "J");
}

static jlong
GetConfigurationObject(JNIEnv *env, jobject thisObj)
{
  jclass torApiClass = (*env)->GetObjectClass(env, thisObj);
  if (torApiClass == NULL) {
    fprintf(stderr, "GetObjectClass returned NULL\n");
    return 0;
  }

  jfieldID torConfigurationField = GetConfigurationFieldID(env, torApiClass);
  if (torConfigurationField == NULL) {
    fprintf(stderr, "The fieldID is NULL\n");
    return 0;
  }

  return (*env)->GetLongField(env, thisObj, torConfigurationField);
}

static bool
SetConfiguration(JNIEnv *env, jobject thisObj,
                 const tor_main_configuration_t* torConfiguration)
{
  jclass torApiClass = (*env)->GetObjectClass(env, thisObj);
  if (torApiClass == NULL) {
    return false;
  }

  jfieldID torConfigurationField = GetConfigurationFieldID(env, torApiClass);
  if (torConfigurationField == NULL) {
    return false;
  }

  jlong cfg = (jlong) torConfiguration;

  (*env)->SetLongField(env, thisObj, torConfigurationField, cfg);
  return true;
}

static tor_main_configuration_t*
GetConfiguration(JNIEnv *env, jobject thisObj)
{
  jlong torConfiguration = GetConfigurationObject(env, thisObj);
  if (torConfiguration == 0) {
    fprintf(stderr, "The long is 0\n");
    return NULL;
  }

  return (tor_main_configuration_t *) torConfiguration;
}

static jfieldID
GetControlSocketFieldID(JNIEnv * const env, jclass torApiClass)
{
  return (*env)->GetFieldID(env, torApiClass, "torControlFd", "I");
}

static bool
SetControlSocket(JNIEnv *env, jobject thisObj, int socket)
{
  jclass torApiClass = (*env)->GetObjectClass(env, thisObj);
  if (torApiClass == NULL) {
    fprintf(stderr, "SetControlSocket: GetObjectClass returned NULL\n");
    return false;
  }

  jfieldID controlFieldId = GetControlSocketFieldID(env, torApiClass);

  (*env)->SetIntField(env, thisObj, controlFieldId, socket);
  return true;
}

static bool
CreateTorConfiguration(JNIEnv *env, jobject thisObj)
{
  jlong torConfiguration = GetConfigurationObject(env, thisObj);
  if (torConfiguration == 0) {
    return false;
  }

  tor_main_configuration_t *tor_config = tor_main_configuration_new();
  if (tor_config == NULL) {
    fprintf(stderr,
            "Allocating and creating a new configuration structure failed.\n");
    return false;
  }

  if (!SetConfiguration(env, thisObj, tor_config)) {
    tor_main_configuration_free(tor_config);
    return false;
  }

  return true;
}

static bool
SetCommandLine(JNIEnv *env, jobject thisObj, jobjectArray arrArgv)
{
  tor_main_configuration_t *cfg = GetConfiguration(env, thisObj);
  if (cfg == NULL) {
    fprintf(stderr, "SetCommandLine: The Tor configuration is NULL!\n");
    return -1;
  }

  jsize arrArgvLen = (*env)->GetArrayLength(env, arrArgv);
  if (arrArgvLen > (INT_MAX-1)) {
    fprintf(stderr, "Too many args\n");
    return false;
  }

  argc = (int) arrArgvLen;
  argv = (char**) tor_malloc(argc * sizeof(char*));
  if (argv == NULL) {
    return false;
  }

  for (jsize i=0; i<argc; i++) {
    jobject objElm = (*env)->GetObjectArrayElement(env, arrArgv, i);
    jstring argElm = (jstring) objElm;
    const char *arg = (*env)->GetStringUTFChars(env, argElm, NULL);
    argv[i] = strdup(arg);
  }

  if (tor_main_configuration_set_command_line(cfg, argc, argv)) {
    fprintf(stderr, "Setting the command line config failed\n");
    return false;
  }
  return true;
}

static int
SetupControlSocket(JNIEnv *env, jobject thisObj)
{
  jclass torApiClass = (*env)->GetObjectClass(env, thisObj);
  if (torApiClass == NULL) {
    fprintf(stderr, "SetupControlSocket: GetObjectClass returned NULL\n");
    return false;
  }

  tor_main_configuration_t *cfg = GetConfiguration(env, thisObj);
  if (cfg == NULL) {
    fprintf(stderr, "SetupControlSocket: The Tor configuration is NULL!\n");
    return false;
  }

  tor_control_socket_t tcs = tor_main_configuration_setup_control_socket(cfg);
  fcntl(tcs, F_SETFL, O_NONBLOCK);
  SetControlSocket(env, thisObj, tcs);
  return true;
}

static int
RunMain(JNIEnv *env, jobject thisObj)
{
  tor_main_configuration_t *cfg = GetConfiguration(env, thisObj);
  if (cfg == NULL) {
    fprintf(stderr, "RunMain: The Tor configuration is NULL!\n");
    return -1;
  }

  int rv = tor_run_main(cfg);
  if (rv != 0) {
    fprintf(stderr, "Tor returned with an error\n");
  } else {
    printf("Tor returned successfully\n");
  }
  return rv;
}

JNIEXPORT jboolean JNICALL
Java_org_torproject_jni_TorService_createTorConfiguration
(JNIEnv *env, jobject thisObj)
{
  return CreateTorConfiguration(env, thisObj);
}

JNIEXPORT jboolean JNICALL
Java_org_torproject_jni_TorService_mainConfigurationSetCommandLine
(JNIEnv *env, jobject thisObj, jobjectArray arrArgv)
{
  return SetCommandLine(env, thisObj, arrArgv);
}

JNIEXPORT jboolean JNICALL
Java_org_torproject_jni_TorService_mainConfigurationSetupControlSocket
(JNIEnv *env, jobject thisObj)
{
  return SetupControlSocket(env, thisObj);
}

JNIEXPORT void JNICALL
Java_org_torproject_jni_TorService_mainConfigurationFree
(JNIEnv *env, jobject thisObj)
{
  tor_main_configuration_t *cfg = GetConfiguration(env, thisObj);
  if (cfg == NULL) {
    fprintf(stderr, "ConfigurationFree: The Tor configuration is NULL!\n");
    return;
  }
  tor_main_configuration_free(cfg);
}

JNIEXPORT jstring JNICALL
Java_org_torproject_jni_TorService_apiGetProviderVersion
(JNIEnv *env, jobject _ignore)
{
  UNUSED(_ignore);
  return (*env)->NewStringUTF(env, tor_api_get_provider_version());
}

JNIEXPORT jint JNICALL
Java_org_torproject_jni_TorService_runMain
(JNIEnv *env, jobject thisObj)
{
  return RunMain(env, thisObj);
}
