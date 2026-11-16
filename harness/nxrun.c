/*
 * nxrun.c — calls OnDev Shield V3's native nx_decrypt() out of libondevx.so
 *           using a synthetic JNIEnv, and dumps the decrypted payload.
 *
 * Build (aarch64 Linux):
 *   cc -O2 -o nxrun nxrun.c -ldl -I$JAVA_HOME/include -I$JAVA_HOME/include/linux
 *
 * Usage:
 *   ./nxrun <libondevx.so> <assets/ondev/k> <assets/ondev/p> <CERT.RSA> <out.bin>
 *
 * The library is stripped of dynsym entries for nx_decrypt (it's a static
 * file-scope function), so we resolve it as base+0x1ea3c in the arm64 build.
 * If that offset is wrong we fall back to scanning for the JNINativeMethod
 * registration table.
 */

#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <link.h>
#include <stdarg.h>
#include <stddef.h>

/* ---- minimal JNI types ---- */
typedef uint8_t  jboolean;
typedef int8_t   jbyte;
typedef uint16_t jchar;
typedef int16_t  jshort;
typedef int32_t  jint;
typedef int64_t  jlong;
typedef float    jfloat;
typedef double   jdouble;
typedef jint     jsize;

struct _jobject;
typedef struct _jobject *jobject;
typedef jobject jclass;
typedef jobject jstring;
typedef jobject jthrowable;
typedef jobject jarray;
typedef jarray  jbooleanArray;
typedef jarray  jbyteArray;
typedef jarray  jcharArray;
typedef jarray  jshortArray;
typedef jarray  jintArray;
typedef jarray  jlongArray;
typedef jarray  jfloatArray;
typedef jarray  jdoubleArray;
typedef jarray  jobjectArray;
typedef union jvalue {
    jboolean z; jbyte b; jchar c; jshort s;
    jint i; jlong j; jfloat f; jdouble d; jobject l;
} jvalue;

struct JNINativeInterface_;
typedef const struct JNINativeInterface_ *JNIEnv;
typedef const struct JNIInvokeInterface_ *JavaVM;

struct JNINativeInterface_ {
    void *reserved0, *reserved1, *reserved2, *reserved3;
    jint     (*GetVersion)(JNIEnv *);
    jclass   (*DefineClass)(JNIEnv *, const char *, jobject, const jbyte *, jsize);
    jclass   (*FindClass)(JNIEnv *, const char *);
    void    *FromReflectedMethod;
    void    *FromReflectedField;
    void    *ToReflectedMethod;
    jclass   (*GetSuperclass)(JNIEnv *, jclass);
    jboolean (*IsAssignableFrom)(JNIEnv *, jclass, jclass);
    void    *ToReflectedField;
    jint     (*Throw)(JNIEnv *, jthrowable);
    jint     (*ThrowNew)(JNIEnv *, jclass, const char *);
    jthrowable (*ExceptionOccurred)(JNIEnv *);
    void     (*ExceptionDescribe)(JNIEnv *);
    void     (*ExceptionClear)(JNIEnv *);
    void     (*FatalError)(JNIEnv *, const char *);
    jint     (*PushLocalFrame)(JNIEnv *, jint);
    jobject  (*PopLocalFrame)(JNIEnv *, jobject);
    jobject  (*NewGlobalRef)(JNIEnv *, jobject);
    void     (*DeleteGlobalRef)(JNIEnv *, jobject);
    void     (*DeleteLocalRef)(JNIEnv *, jobject);
    jboolean (*IsSameObject)(JNIEnv *, jobject, jobject);
    jobject  (*NewLocalRef)(JNIEnv *, jobject);
    jint     (*EnsureLocalCapacity)(JNIEnv *, jint);
    jobject  (*AllocObject)(JNIEnv *, jclass);
    jobject  (*NewObject)(JNIEnv *, jclass, void *);
    jobject  (*NewObjectV)(JNIEnv *, jclass, void *, va_list);
    jobject  (*NewObjectA)(JNIEnv *, jclass, void *, const jvalue *);
    jclass   (*GetObjectClass)(JNIEnv *, jobject);
    jboolean (*IsInstanceOf)(JNIEnv *, jobject, jclass);
    void    *GetMethodID;
    jobject  (*CallObjectMethod)(JNIEnv *, jobject, void *, ...);
    jobject  (*CallObjectMethodV)(JNIEnv *, jobject, void *, va_list);
    jobject  (*CallObjectMethodA)(JNIEnv *, jobject, void *, const jvalue *);
    jboolean (*CallBooleanMethod)(JNIEnv *, jobject, void *, ...);
    jboolean (*CallBooleanMethodV)(JNIEnv *, jobject, void *, va_list);
    jboolean (*CallBooleanMethodA)(JNIEnv *, jobject, void *, const jvalue *);
    jbyte    (*CallByteMethod)(JNIEnv *, jobject, void *, ...);
    jbyte    (*CallByteMethodV)(JNIEnv *, jobject, void *, va_list);
    jbyte    (*CallByteMethodA)(JNIEnv *, jobject, void *, const jvalue *);
    jchar    (*CallCharMethod)(JNIEnv *, jobject, void *, ...);
    jchar    (*CallCharMethodV)(JNIEnv *, jobject, void *, va_list);
    jchar    (*CallCharMethodA)(JNIEnv *, jobject, void *, const jvalue *);
    jshort   (*CallShortMethod)(JNIEnv *, jobject, void *, ...);
    jshort   (*CallShortMethodV)(JNIEnv *, jobject, void *, va_list);
    jshort   (*CallShortMethodA)(JNIEnv *, jobject, void *, const jvalue *);
    jint     (*CallIntMethod)(JNIEnv *, jobject, void *, ...);
    jint     (*CallIntMethodV)(JNIEnv *, jobject, void *, va_list);
    jint     (*CallIntMethodA)(JNIEnv *, jobject, void *, const jvalue *);
    jlong    (*CallLongMethod)(JNIEnv *, jobject, void *, ...);
    jlong    (*CallLongMethodV)(JNIEnv *, jobject, void *, va_list);
    jlong    (*CallLongMethodA)(JNIEnv *, jobject, void *, const jvalue *);
    jfloat   (*CallFloatMethod)(JNIEnv *, jobject, void *, ...);
    jfloat   (*CallFloatMethodV)(JNIEnv *, jobject, void *, va_list);
    jfloat   (*CallFloatMethodA)(JNIEnv *, jobject, void *, const jvalue *);
    jdouble  (*CallDoubleMethod)(JNIEnv *, jobject, void *, ...);
    jdouble  (*CallDoubleMethodV)(JNIEnv *, jobject, void *, va_list);
    jdouble  (*CallDoubleMethodA)(JNIEnv *, jobject, void *, const jvalue *);
    void     (*CallVoidMethod)(JNIEnv *, jobject, void *, ...);
    void     (*CallVoidMethodV)(JNIEnv *, jobject, void *, va_list);
    void     (*CallVoidMethodA)(JNIEnv *, jobject, void *, const jvalue *);
    jobject  (*CallNonvirtualObjectMethod)(JNIEnv *, jobject, jclass, void *, ...);
    jobject  (*CallNonvirtualObjectMethodV)(JNIEnv *, jobject, jclass, void *, va_list);
    jobject  (*CallNonvirtualObjectMethodA)(JNIEnv *, jobject, jclass, void *, const jvalue *);
    jboolean (*CallNonvirtualBooleanMethod)(JNIEnv *, jobject, jclass, void *, ...);
    jboolean (*CallNonvirtualBooleanMethodV)(JNIEnv *, jobject, jclass, void *, va_list);
    jboolean (*CallNonvirtualBooleanMethodA)(JNIEnv *, jobject, jclass, void *, const jvalue *);
    jbyte    (*CallNonvirtualByteMethod)(JNIEnv *, jobject, jclass, void *, ...);
    jbyte    (*CallNonvirtualByteMethodV)(JNIEnv *, jobject, jclass, void *, va_list);
    jbyte    (*CallNonvirtualByteMethodA)(JNIEnv *, jobject, jclass, void *, const jvalue *);
    jchar    (*CallNonvirtualCharMethod)(JNIEnv *, jobject, jclass, void *, ...);
    jchar    (*CallNonvirtualCharMethodV)(JNIEnv *, jobject, jclass, void *, va_list);
    jchar    (*CallNonvirtualCharMethodA)(JNIEnv *, jobject, jclass, void *, const jvalue *);
    jshort   (*CallNonvirtualShortMethod)(JNIEnv *, jobject, jclass, void *, ...);
    jshort   (*CallNonvirtualShortMethodV)(JNIEnv *, jobject, jclass, void *, va_list);
    jshort   (*CallNonvirtualShortMethodA)(JNIEnv *, jobject, jclass, void *, const jvalue *);
    jint     (*CallNonvirtualIntMethod)(JNIEnv *, jobject, jclass, void *, ...);
    jint     (*CallNonvirtualIntMethodV)(JNIEnv *, jobject, jclass, void *, va_list);
    jint     (*CallNonvirtualIntMethodA)(JNIEnv *, jobject, jclass, void *, const jvalue *);
    jlong    (*CallNonvirtualLongMethod)(JNIEnv *, jobject, jclass, void *, ...);
    jlong    (*CallNonvirtualLongMethodV)(JNIEnv *, jobject, jclass, void *, va_list);
    jlong    (*CallNonvirtualLongMethodA)(JNIEnv *, jobject, jclass, void *, const jvalue *);
    jfloat   (*CallNonvirtualFloatMethod)(JNIEnv *, jobject, jclass, void *, ...);
    jfloat   (*CallNonvirtualFloatMethodV)(JNIEnv *, jobject, jclass, void *, va_list);
    jfloat   (*CallNonvirtualFloatMethodA)(JNIEnv *, jobject, jclass, void *, const jvalue *);
    jdouble  (*CallNonvirtualDoubleMethod)(JNIEnv *, jobject, jclass, void *, ...);
    jdouble  (*CallNonvirtualDoubleMethodV)(JNIEnv *, jobject, jclass, void *, va_list);
    jdouble  (*CallNonvirtualDoubleMethodA)(JNIEnv *, jobject, jclass, void *, const jvalue *);
    void     (*CallNonvirtualVoidMethod)(JNIEnv *, jobject, jclass, void *, ...);
    void     (*CallNonvirtualVoidMethodV)(JNIEnv *, jobject, jclass, void *, va_list);
    void     (*CallNonvirtualVoidMethodA)(JNIEnv *, jobject, jclass, void *, const jvalue *);
    void    *GetFieldID;
    jobject  (*GetObjectField)(JNIEnv *, jobject, void *);
    jboolean (*GetBooleanField)(JNIEnv *, jobject, void *);
    jbyte    (*GetByteField)(JNIEnv *, jobject, void *);
    jchar    (*GetCharField)(JNIEnv *, jobject, void *);
    jshort   (*GetShortField)(JNIEnv *, jobject, void *);
    jint     (*GetIntField)(JNIEnv *, jobject, void *);
    jlong    (*GetLongField)(JNIEnv *, jobject, void *);
    jfloat   (*GetFloatField)(JNIEnv *, jobject, void *);
    jdouble  (*GetDoubleField)(JNIEnv *, jobject, void *);
    void     (*SetObjectField)(JNIEnv *, jobject, void *, jobject);
    void     (*SetBooleanField)(JNIEnv *, jobject, void *, jboolean);
    void     (*SetByteField)(JNIEnv *, jobject, void *, jbyte);
    void     (*SetCharField)(JNIEnv *, jobject, void *, jchar);
    void     (*SetShortField)(JNIEnv *, jobject, void *, jshort);
    void     (*SetIntField)(JNIEnv *, jobject, void *, jint);
    void     (*SetLongField)(JNIEnv *, jobject, void *, jlong);
    void     (*SetFloatField)(JNIEnv *, jobject, void *, jfloat);
    void     (*SetDoubleField)(JNIEnv *, jobject, void *, jdouble);
    void    *GetStaticMethodID;
    jobject  (*CallStaticObjectMethod)(JNIEnv *, jclass, void *, ...);
    jobject  (*CallStaticObjectMethodV)(JNIEnv *, jclass, void *, va_list);
    jobject  (*CallStaticObjectMethodA)(JNIEnv *, jclass, void *, const jvalue *);
    jboolean (*CallStaticBooleanMethod)(JNIEnv *, jclass, void *, ...);
    jboolean (*CallStaticBooleanMethodV)(JNIEnv *, jclass, void *, va_list);
    jboolean (*CallStaticBooleanMethodA)(JNIEnv *, jclass, void *, const jvalue *);
    jbyte    (*CallStaticByteMethod)(JNIEnv *, jclass, void *, ...);
    jbyte    (*CallStaticByteMethodV)(JNIEnv *, jclass, void *, va_list);
    jbyte    (*CallStaticByteMethodA)(JNIEnv *, jclass, void *, const jvalue *);
    jchar    (*CallStaticCharMethod)(JNIEnv *, jclass, void *, ...);
    jchar    (*CallStaticCharMethodV)(JNIEnv *, jclass, void *, va_list);
    jchar    (*CallStaticCharMethodA)(JNIEnv *, jclass, void *, const jvalue *);
    jshort   (*CallStaticShortMethod)(JNIEnv *, jclass, void *, ...);
    jshort   (*CallStaticShortMethodV)(JNIEnv *, jclass, void *, va_list);
    jshort   (*CallStaticShortMethodA)(JNIEnv *, jclass, void *, const jvalue *);
    jint     (*CallStaticIntMethod)(JNIEnv *, jclass, void *, ...);
    jint     (*CallStaticIntMethodV)(JNIEnv *, jclass, void *, va_list);
    jint     (*CallStaticIntMethodA)(JNIEnv *, jclass, void *, const jvalue *);
    jlong    (*CallStaticLongMethod)(JNIEnv *, jclass, void *, ...);
    jlong    (*CallStaticLongMethodV)(JNIEnv *, jclass, void *, va_list);
    jlong    (*CallStaticLongMethodA)(JNIEnv *, jclass, void *, const jvalue *);
    jfloat   (*CallStaticFloatMethod)(JNIEnv *, jclass, void *, ...);
    jfloat   (*CallStaticFloatMethodV)(JNIEnv *, jclass, void *, va_list);
    jfloat   (*CallStaticFloatMethodA)(JNIEnv *, jclass, void *, const jvalue *);
    jdouble  (*CallStaticDoubleMethod)(JNIEnv *, jclass, void *, ...);
    jdouble  (*CallStaticDoubleMethodV)(JNIEnv *, jclass, void *, va_list);
    jdouble  (*CallStaticDoubleMethodA)(JNIEnv *, jclass, void *, const jvalue *);
    void     (*CallStaticVoidMethod)(JNIEnv *, jclass, void *, ...);
    void     (*CallStaticVoidMethodV)(JNIEnv *, jclass, void *, va_list);
    void     (*CallStaticVoidMethodA)(JNIEnv *, jclass, void *, const jvalue *);
    void    *GetStaticFieldID;
    jobject  (*GetStaticObjectField)(JNIEnv *, jclass, void *);
    jboolean (*GetStaticBooleanField)(JNIEnv *, jclass, void *);
    jbyte    (*GetStaticByteField)(JNIEnv *, jclass, void *);
    jchar    (*GetStaticCharField)(JNIEnv *, jclass, void *);
    jshort   (*GetStaticShortField)(JNIEnv *, jclass, void *);
    jint     (*GetStaticIntField)(JNIEnv *, jclass, void *);
    jlong    (*GetStaticLongField)(JNIEnv *, jclass, void *);
    jfloat   (*GetStaticFloatField)(JNIEnv *, jclass, void *);
    jdouble  (*GetStaticDoubleField)(JNIEnv *, jclass, void *);
    void     (*SetStaticObjectField)(JNIEnv *, jclass, void *, jobject);
    void     (*SetStaticBooleanField)(JNIEnv *, jclass, void *, jboolean);
    void     (*SetStaticByteField)(JNIEnv *, jclass, void *, jbyte);
    void     (*SetStaticCharField)(JNIEnv *, jclass, void *, jchar);
    void     (*SetStaticShortField)(JNIEnv *, jclass, void *, jshort);
    void     (*SetStaticIntField)(JNIEnv *, jclass, void *, jint);
    void     (*SetStaticLongField)(JNIEnv *, jclass, void *, jlong);
    void     (*SetStaticFloatField)(JNIEnv *, jclass, void *, jfloat);
    void     (*SetStaticDoubleField)(JNIEnv *, jclass, void *, jdouble);
    jstring  (*NewString)(JNIEnv *, const jchar *, jsize);
    jsize    (*GetStringLength)(JNIEnv *, jstring);
    const jchar *(*GetStringChars)(JNIEnv *, jstring, jboolean *);
    void     (*ReleaseStringChars)(JNIEnv *, jstring, const jchar *);
    jstring  (*NewStringUTF)(JNIEnv *, const char *);
    jsize    (*GetStringUTFLength)(JNIEnv *, jstring);
    const char *(*GetStringUTFChars)(JNIEnv *, jstring, jboolean *);
    void     (*ReleaseStringUTFChars)(JNIEnv *, jstring, const char *);
    jsize    (*GetArrayLength)(JNIEnv *, jarray);
    jobjectArray (*NewObjectArray)(JNIEnv *, jsize, jclass, jobject);
    jobject  (*GetObjectArrayElement)(JNIEnv *, jobjectArray, jsize);
    void     (*SetObjectArrayElement)(JNIEnv *, jobjectArray, jsize, jobject);
    jbooleanArray (*NewBooleanArray)(JNIEnv *, jsize);
    jbyteArray (*NewByteArray)(JNIEnv *, jsize);
    jcharArray (*NewCharArray)(JNIEnv *, jsize);
    jshortArray (*NewShortArray)(JNIEnv *, jsize);
    jintArray (*NewIntArray)(JNIEnv *, jsize);
    jlongArray (*NewLongArray)(JNIEnv *, jsize);
    jfloatArray (*NewFloatArray)(JNIEnv *, jsize);
    jdoubleArray (*NewDoubleArray)(JNIEnv *, jsize);
    jboolean *(*GetBooleanArrayElements)(JNIEnv *, jbooleanArray, jboolean *);
    jbyte    *(*GetByteArrayElements)(JNIEnv *, jbyteArray, jboolean *);
    jchar    *(*GetCharArrayElements)(JNIEnv *, jcharArray, jboolean *);
    jshort   *(*GetShortArrayElements)(JNIEnv *, jshortArray, jboolean *);
    jint     *(*GetIntArrayElements)(JNIEnv *, jintArray, jboolean *);
    jlong    *(*GetLongArrayElements)(JNIEnv *, jlongArray, jboolean *);
    jfloat   *(*GetFloatArrayElements)(JNIEnv *, jfloatArray, jboolean *);
    jdouble  *(*GetDoubleArrayElements)(JNIEnv *, jdoubleArray, jboolean *);
    void     (*ReleaseBooleanArrayElements)(JNIEnv *, jbooleanArray, jboolean *, jint);
    void     (*ReleaseByteArrayElements)(JNIEnv *, jbyteArray, jbyte *, jint);
    void     (*ReleaseCharArrayElements)(JNIEnv *, jcharArray, jchar *, jint);
    void     (*ReleaseShortArrayElements)(JNIEnv *, jshortArray, jshort *, jint);
    void     (*ReleaseIntArrayElements)(JNIEnv *, jintArray, jint *, jint);
    void     (*ReleaseLongArrayElements)(JNIEnv *, jlongArray, jlong *, jint);
    void     (*ReleaseFloatArrayElements)(JNIEnv *, jfloatArray, jfloat *, jint);
    void     (*ReleaseDoubleArrayElements)(JNIEnv *, jdoubleArray, jdouble *, jint);
    void     (*GetBooleanArrayRegion)(JNIEnv *, jbooleanArray, jsize, jsize, jboolean *);
    void     (*GetByteArrayRegion)(JNIEnv *, jbyteArray, jsize, jsize, jbyte *);
    void     (*GetCharArrayRegion)(JNIEnv *, jcharArray, jsize, jsize, jchar *);
    void     (*GetShortArrayRegion)(JNIEnv *, jshortArray, jsize, jsize, jshort *);
    void     (*GetIntArrayRegion)(JNIEnv *, jintArray, jsize, jsize, jint *);
    void     (*GetLongArrayRegion)(JNIEnv *, jlongArray, jsize, jsize, jlong *);
    void     (*GetFloatArrayRegion)(JNIEnv *, jfloatArray, jsize, jsize, jfloat *);
    void     (*GetDoubleArrayRegion)(JNIEnv *, jdoubleArray, jsize, jsize, jdouble *);
    void     (*SetBooleanArrayRegion)(JNIEnv *, jbooleanArray, jsize, jsize, const jboolean *);
    void     (*SetByteArrayRegion)(JNIEnv *, jbyteArray, jsize, jsize, const jbyte *);
    void     (*SetCharArrayRegion)(JNIEnv *, jcharArray, jsize, jsize, const jchar *);
    void     (*SetShortArrayRegion)(JNIEnv *, jshortArray, jsize, jsize, const jshort *);
    void     (*SetIntArrayRegion)(JNIEnv *, jintArray, jsize, jsize, const jint *);
    void     (*SetLongArrayRegion)(JNIEnv *, jlongArray, jsize, jsize, const jlong *);
    void     (*SetFloatArrayRegion)(JNIEnv *, jfloatArray, jsize, jsize, const jfloat *);
    void     (*SetDoubleArrayRegion)(JNIEnv *, jdoubleArray, jsize, jsize, const jdouble *);
    jint     (*RegisterNatives)(JNIEnv *, jclass, const void *, jint);
    jint     (*UnregisterNatives)(JNIEnv *, jclass);
    jint     (*MonitorEnter)(JNIEnv *, jobject);
    jint     (*MonitorExit)(JNIEnv *, jobject);
    jint     (*GetJavaVM)(JNIEnv *, JavaVM *);
    void     (*GetStringRegion)(JNIEnv *, jstring, jsize, jsize, jchar *);
    void     (*GetStringUTFRegion)(JNIEnv *, jstring, jsize, jsize, char *);
    void    *(*GetPrimitiveArrayCritical)(JNIEnv *, jarray, jboolean *);
    void     (*ReleasePrimitiveArrayCritical)(JNIEnv *, jarray, void *, jint);
    const jchar *(*GetStringCritical)(JNIEnv *, jstring, jboolean *);
    void     (*ReleaseStringCritical)(JNIEnv *, jstring, const jchar *);
    jobject  (*NewWeakGlobalRef)(JNIEnv *, jobject);
    void     (*DeleteWeakGlobalRef)(JNIEnv *, jobject);
    jboolean (*ExceptionCheck)(JNIEnv *);
    jobject  (*NewDirectByteBuffer)(JNIEnv *, void *, jlong);
    void     *(*GetDirectBufferAddress)(JNIEnv *, jobject);
    jlong    (*GetDirectBufferCapacity)(JNIEnv *, jobject);
    void    *GetObjectRefType;
};

/* ================= synthetic JNIEnv ================= */

/* fake java "objects": we only need distinct non-null handles */
typedef struct { int kind; void *data; size_t len; } FakeObj;

static FakeObj **g_arrays = NULL;
static size_t  g_narr = 0;

static FakeObj *obj_new(int kind) {
    FakeObj *o = calloc(1, sizeof(*o));
    o->kind = kind;
    return o;
}

static jsize f_GetArrayLength(JNIEnv *e, jarray a) {
    FakeObj *o = (FakeObj *)a;
    jsize n = o ? (jsize)o->len : 0;
    fprintf(stderr, "   GetArrayLength(kind=%d) = %d\n", o ? o->kind : -1, (int)n);
    return n;
}

static void f_GetByteArrayRegion(JNIEnv *e, jbyteArray a, jsize start, jsize len, jbyte *buf) {
    FakeObj *o = (FakeObj *)a;
    fprintf(stderr, "   GetByteArrayRegion(kind=%d,start=%d,len=%d)\n", o ? o->kind : -1, start, len);
    if (!o || !o->data) return;
    if (start + len > (jsize)o->len) return;
    memcpy(buf, (uint8_t *)o->data + start, len);
}

static jclass f_FindClass(JNIEnv *e, const char *name) {
    fprintf(stderr, "   FindClass(%s)\n", name ? name : "null");
    return (jclass)obj_new(100);
}

static jobjectArray f_NewObjectArray(JNIEnv *e, jsize len, jclass cls, jobject init) {
    fprintf(stderr, "   NewObjectArray(len=%d)\n", len);
    FakeObj *o = obj_new(200);
    o->data = calloc((size_t)len, sizeof(FakeObj *));
    o->len = (size_t)len;
    return (jobjectArray)o;
}

static void f_SetObjectArrayElement(JNIEnv *e, jobjectArray a, jsize idx, jobject v) {
    FakeObj *o = (FakeObj *)a;
    if (!o || idx < 0 || (size_t)idx >= o->len) return;
    ((FakeObj **)o->data)[idx] = (FakeObj *)v;
    fprintf(stderr, "   SetObjectArrayElement[%d]\n", idx);
}

static jobject f_NewDirectByteBuffer(JNIEnv *e, void *addr, jlong cap) {
    fprintf(stderr, "   NewDirectByteBuffer(addr=%p, cap=%lld)\n", addr, (long long)cap);
    FakeObj *o = obj_new(300);
    o->data = addr;
    o->len = (size_t)cap;
    return (jobject)o;
}

static jint f_GetVersion(JNIEnv *e) { return 0x00010008; }

static struct JNINativeInterface_ g_vtab;

/* C++ JNIEnv is a *pointer* to a struct whose first member is the vtable
 * pointer. Passing &vtab directly makes env->functions dereference the first
 * function pointer (GetVersion) instead of the table. */
struct JNIEnvWrapper { const struct JNINativeInterface_ *functions; };
static struct JNIEnvWrapper g_env;

static void build_jni(void) {
    memset(&g_vtab, 0, sizeof(g_vtab));
    g_env.functions = &g_vtab;
    g_vtab.GetVersion = f_GetVersion;
    g_vtab.FindClass = f_FindClass;
    g_vtab.GetArrayLength = f_GetArrayLength;
    g_vtab.NewObjectArray = f_NewObjectArray;
    g_vtab.SetObjectArrayElement = f_SetObjectArrayElement;
    g_vtab.GetByteArrayRegion = f_GetByteArrayRegion;
    g_vtab.NewDirectByteBuffer = f_NewDirectByteBuffer;
}

/* ================= helpers ================= */

static uint8_t *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc((size_t)n);
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(b); return NULL; }
    fclose(f);
    *out_len = (size_t)n;
    return b;
}

/* sha256 (self-contained, no openssl dependency) */
typedef struct { uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t n; } SHA256;
static const uint32_t K256[64] = {
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
static void sha256_block(SHA256 *s, const uint8_t *p) {
    uint32_t w[64], a,b,c,d,e,f,g,h,t1,t2;
    for (int i=0;i<16;i++) w[i]=(uint32_t)p[i*4]<<24|(uint32_t)p[i*4+1]<<16|(uint32_t)p[i*4+2]<<8|p[i*4+3];
    for (int i=16;i<64;i++){
        uint32_t s0=ROR(w[i-15],7)^ROR(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1=ROR(w[i-2],17)^ROR(w[i-2],19)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    a=s->h[0];b=s->h[1];c=s->h[2];d=s->h[3];e=s->h[4];f=s->h[5];g=s->h[6];h=s->h[7];
    for(int i=0;i<64;i++){
        t1=h+(ROR(e,6)^ROR(e,11)^ROR(e,25))+((e&f)^(~e&g))+K256[i]+w[i];
        t2=(ROR(a,2)^ROR(a,13)^ROR(a,22))+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
static void sha256_init(SHA256 *s){
    s->h[0]=0x6a09e667;s->h[1]=0xbb67ae85;s->h[2]=0x3c6ef372;s->h[3]=0xa54ff53a;
    s->h[4]=0x510e527f;s->h[5]=0x9b05688c;s->h[6]=0x1f83d9ab;s->h[7]=0x5be0cd19;
    s->len=0;s->n=0;
}
static void sha256_update(SHA256 *s,const uint8_t *p,size_t n){
    s->len+=n;
    while(n){
        size_t k=64-s->n; if(k>n)k=n;
        memcpy(s->buf+s->n,p,k); s->n+=k; p+=k; n-=k;
        if(s->n==64){ sha256_block(s,s->buf); s->n=0; }
    }
}
static void sha256_final(SHA256 *s,uint8_t out[32]){
    uint64_t bits=s->len*8; uint8_t pad=0x80;
    sha256_update(s,&pad,1);
    uint8_t z=0;
    while(s->n!=56) sha256_update(s,&z,1);
    uint8_t lb[8];
    for(int i=0;i<8;i++) lb[i]=(uint8_t)(bits>>(56-8*i));
    sha256_update(s,lb,8);
    for(int i=0;i<8;i++){ out[i*4]=(uint8_t)(s->h[i]>>24); out[i*4+1]=(uint8_t)(s->h[i]>>16);
                          out[i*4+2]=(uint8_t)(s->h[i]>>8); out[i*4+3]=(uint8_t)s->h[i]; }
}

/* ================= main ================= */

typedef jobjectArray (*nx_decrypt_t)(JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray);

int main(int argc, char **argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: %s <libondevx.so> <k> <p> <CERT.RSA> <out.bin> [nx_decrypt_offset]\n", argv[0]);
        return 2;
    }
    const char *libpath = argv[1];
    const char *kpath   = argv[2];
    const char *ppath   = argv[3];
    const char *certpath= argv[4];
    const char *outpath = argv[5];
    unsigned long long off = 0x1ea3cULL;
    if (argc > 6) off = strtoull(argv[6], NULL, 0);

    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    build_jni();
    fprintf(stderr, "== step 1: dlopen %s\n", libpath);

    void *h = dlopen(libpath, RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "dlopen failed: %s\n", dlerror()); return 3; }
    fprintf(stderr, "== step 2: dlopen OK, l_addr lookup...\n");

    /* find load base via link_map */
    struct link_map *lm = NULL;
    if (dlinfo(h, RTLD_DI_LINKMAP, &lm) != 0 || !lm) { fprintf(stderr, "dlinfo failed\n"); return 3; }
    uintptr_t base = (uintptr_t)lm->l_addr;
    nx_decrypt_t fn = (nx_decrypt_t)(base + off);
    fprintf(stderr, "lib base = %p, nx_decrypt = %p (offset 0x%llx)\n", (void*)base, (void*)fn, off);

    size_t klen, plen, clen;
    uint8_t *kb = read_file(kpath, &klen);
    uint8_t *pb = read_file(ppath, &plen);
    uint8_t *cb = read_file(certpath, &clen);
    if (!kb || !pb) { fprintf(stderr, "input read failed\n"); return 4; }
    fprintf(stderr, "k=%zu p=%zu cert=%zu\n", klen, plen, clen);

    /* ShellAppFactoryV3.certSetHashFromApk():
     *   CertificateFactory X.509 -> generateCertificates(CERT.RSA)
     *   for each cert: sha256(cert.getEncoded())      <- ONE hash only
     * And getEncoded() is the raw X.509 DER, not the PKCS#7 container,
     * so input/cert.der must be the extracted certificate (see workflow). */
    uint8_t h2[32];
    SHA256 s;
    if (cb && clen) {
        sha256_init(&s); sha256_update(&s, cb, clen); sha256_final(&s, h2);
        fprintf(stderr, "certHash = sha256(X.509 DER) = ");
        for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", h2[i]);
        fprintf(stderr, "\n");
    }

    FakeObj *ak = obj_new(1); ak->data = kb; ak->len = klen;
    FakeObj *ap = obj_new(2); ap->data = pb; ap->len = plen;
    FakeObj *ac = obj_new(3); ac->data = h2; ac->len = 32;

    /* ---- direct hkdf probe ------------------------------------------
     * hkdf(saltPtr, ikmPtr, ikmLen, outPtr)  @ 0x20488
     *   saltLen is hardcoded to 16 inside; info = "ondev-dexkey-v2" (15 B);
     *   outLen = 0x30 (48) => key[32] || iv[16].
     * Call site 0x1ed8c: salt = k+5, ikm = secret vector, out = stack buf.
     */
    {
        typedef void (*hkdf_t)(const uint8_t *, const uint8_t *, size_t, uint8_t *);
        hkdf_t hk = (hkdf_t)(base + 0x20488);
        static uint8_t ikm[64];
        static const uint8_t c32[32] = {
            0x69,0xec,0x6c,0xf5,0x99,0xf8,0xe3,0x68,0x8f,0x3c,0x6a,0xb8,0xb8,0xad,0x98,0x18,
            0xf5,0xd1,0x4a,0x0d,0x4a,0x76,0x7d,0xf3,0x3f,0x69,0xbc,0xfe,0xea,0xd9,0xa3,0xef};
        uint8_t ks[48];
        size_t ikmlen = 32;
        memcpy(ikm, c32, 32);
        if (kb && klen >= 5 && kb[4] == 0x11) { memcpy(ikm + 32, h2, 32); ikmlen = 64; }
        memset(ks, 0, sizeof ks);
        fprintf(stderr, "== hkdf probe: kFlag=0x%02x ikmLen=%zu\n", kb ? kb[4] : 0, ikmlen);
        fprintf(stderr, "   salt = ");
        for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", kb[5 + i]);
        fprintf(stderr, "\n");
        hk(kb + 5, ikm, ikmlen, ks);
        fprintf(stderr, "   keystream48 = ");
        for (int i = 0; i < 48; i++) fprintf(stderr, "%02x", ks[i]);
        fprintf(stderr, "\n");
        fprintf(stderr, "   key = ");
        for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", kb[21 + i] ^ ks[i]);
        fprintf(stderr, "\n   iv  = ");
        for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", kb[53 + i] ^ ks[32 + i]);
        fprintf(stderr, "\n");
    }
    /* ------------------------------------------------------------------ */

    if (getenv("NXRUN_TRAP")) {
        FILE *tf = fopen("nxaddr.txt", "w");
        if (tf) {
            fprintf(tf, "%p %p\n", (void *)fn, (void *)base);
            fclose(tf);
        }
        fprintf(stderr, "NXRUN_TRAP: nx_decrypt=%p base=%p\n", (void *)fn, (void *)base);
        if (getenv("NXRUN_STOP")) {
            raise(SIGSTOP);       /* gdb: set breakpoints, then signal SIGCONT */
        } else {
            *(volatile int *)0 = 1;   /* SIGSEGV with the stack live */
        }
    }
    fprintf(stderr, "calling nx_decrypt...\n");
    /* DWARF from the arm64 build:
     *   nx_decrypt(env, clazz, kBlob, pCipher, certHash)
     *   ondevx.cpp:379
     */
    jobjectArray ret = fn(&g_env, (jclass)0, (jbyteArray)ak, (jbyteArray)ap, (jbyteArray)ac);
    fprintf(stderr, "nx_decrypt returned %p\n", (void*)ret);
    if (!ret) { fprintf(stderr, "NULL — decrypt rejected (wrong cert hash or key)\n"); return 5; }

    FakeObj *arr = (FakeObj *)ret;
    fprintf(stderr, "slices = %zu\n", arr->len);
    FILE *o = fopen(outpath, "wb");
    if (!o) { perror(outpath); return 6; }
    size_t total = 0;
    for (size_t i = 0; i < arr->len; i++) {
        FakeObj *sl = ((FakeObj **)arr->data)[i];
        if (!sl) continue;
        fprintf(stderr, "  slice %zu: %zu bytes @ %p\n", i, sl->len, sl->data);
        fwrite(sl->data, 1, sl->len, o);
        total += sl->len;
    }
    fclose(o);
    fprintf(stderr, "wrote %zu bytes to %s\n", total, outpath);
    return 0;
}
