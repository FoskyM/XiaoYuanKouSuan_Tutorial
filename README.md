# XiaoYuanKouSuan_Tutorial
小猿口算思路讲解，V2加密接口解密，PK 场达 0.0 秒（开局即提交）原理，过大学生验证原理，不纂改 js 文件和响应包。
![PixPin_2024-10-12_22-38-01](https://github.com/user-attachments/assets/e0449225-76bb-4fad-a982-25a31d78c460)

## 前言
本笔记只针对小猿口算的 PK 场进行思路讲解，不包含实际代码。

学习靠自己，代码勿 CV。教程放这里，理解其中意。

## 使用技术
LSPosed + WebViewPP + chrome-remote-interface + Frida + adb + mitmproxy

## 思路
使用 LSPosed + WebViewPP 开启远程调试，\
通过 adb 连接模拟器以便进行远程调试，\
使用 chrome-remote-interface 对 webview 进行操作，\
使用 frida hook 拦截解密数据，\
mitmproxy 用于判断请求流程（因为小猿一个 PK 会创建多个 webview，不方便远程调试，我们远程调试只调试发起 PK 后的页面）

## 页面
- pk.html PK 主页
- exercise.html 发起 PK 后页面
- result.html PK 结果页
- motivation-honor-roll.html 排行榜页

## 逆向
这里我只写了关键点，更多逆向笔记可看 [小猿口算逆向笔记](https://github.com/xmexg/xyks/blob/master/frida/readme.md)


### APP 端
#### package com.fenbi.android.leo.webapp.secure.LeoSecureWebViewApi

```java
package com.fenbi.android.leo.webapp.secure.LeoSecureWebViewApi;

public final class LeoSecureWebViewApi extends Object implements a, b	// class@0029cf
{
  // ...
    public final void dataDecrypt(String p0){
        // ...
        // 使用 LeoSecureWebViewApi$b 传输
            this.c.post(new LeoSecureWebViewApi$b(obj3, this, obj));
        // ...
    }

    public final void dataEncrypt(String p0){
        // 使用 LeoSecureWebViewApi$c 传输
            this.c.post(new LeoSecureWebViewApi$c(obj3, this, obj));
        // ...
    }
    // ...
}
```
其中 obj3 为 *com.yuanfudao.android.common.webview.base.JsBridgeBean*

#### package com.yuanfudao.android.common.webview.base.JsBridgeBean

```java
public abstract class JsBridgeBean extends Object implements Serializable	// class@000b95
{
    private String callbackStr;
    private String trigger;

    public void JsBridgeBean(){
       super();
       this.callbackStr = "";
       this.trigger = "";
    }
    public final void callback$com_yuanfudao_android_common_yfd_android_common_webview_interface(a p0){
       y.h(p0, "webView");
       if (l.B(this.callbackStr)) {
          return;
       }
       byte[] bytes = "[null]".getBytes(d.b);
       y.c(bytes, "\(this as java.lang.String\).getBytes\(charset\)");
       p0.loadUrl(new StringBuilder()+"javascript:\(window."+this.callbackStr+" && window."+this.callbackStr+"\(\""+Base64.encodeToString(bytes, 0)+"\"\)\)");
    }
    public final String getCallbackStr$com_yuanfudao_android_common_yfd_android_common_webview_interface(){
       return this.callbackStr;
    }
    public final boolean hasTrigger(){
       return (l.B(this.trigger) ^ 0x01);
    }
    public final void setCallbackStr$com_yuanfudao_android_common_yfd_android_common_webview_interface(String p0){
       y.h(p0, "<set-?>");
       this.callbackStr = p0;
    }
    public final boolean trigger(a p0,Integer p1,Object[] p2){
       y.h(p0, "webView");
       y.h(p2, "data");
       return this.trigger(this.trigger, p0, p1, Arrays.copyOf(p2, p2.length));
    }
    public final boolean trigger(String p0,a p1,Integer p2,Object[] p3){
       Object[] objArray = p3;
       y.h(p1, "webView");
       y.h(objArray, "data");
       if (p0 == null || l.B(p0)) {
          return false;
       }
       int i = (!objArray.length)? 1: 0;
       String str = (i ^ 1)? j.s0(p3, ",", ",", null, 0, null, JsBridgeBean$trigger$dataStr$1.INSTANCE, 28, null): "";
       str = new StringBuilder().append('[').append(p2).append(str).append(']').toString();
       Charset b = d.b;
       if (str != null) {
          byte[] bytes = str.getBytes(b);
          y.c(bytes, "\(this as java.lang.String\).getBytes\(charset\)");
          String str1 = Base64.encodeToString(bytes, false);
          y.c(str1, "Base64.encodeToString\(pa…eArray\(\), Base64.DEFAULT\)");
          p1.post(new JsBridgeBean$a(p1, p0, l.I(str1, "\n", "", false, 4, null)));
          return 1;
       }else {
          throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
       }
    }
}
```

#### package com.yuanfudao.android.common.webview.base.JsBridgeBean$a

```java
public final class JsBridgeBean$a extends Object implements Runnable	// class@000b93
{
    public final a a;
    public final String b;
    public final String c;

    public void JsBridgeBean$a(a p0,String p1,String p2){
       this.a = p0;
       this.b = p1;
       this.c = p2;
       super();
    }
    public final void run(){
       this.a.loadUrl(new StringBuilder()+"javascript:\(window."+this.b+" && window."+this.b+"\(\""+this.c+"\"\)\)");
    }
}
```

阅读代码可以理解其作用是在 WebView 中执行 window.\[callback\](callbackArgString)

callback: name_timestamp_randint，例如 dataDecrypt_1728797281_14，一次性调用，用后即焚

callbackArgString: 经过 base64 编码后的参数

### 网页端
#### @/hooks/exercise/exercise.ts
可以看到 V2 接口仅仅使用 DecryptData 进行解密，跳到 @/utils/EncryptData 就知道调用的是 dataDecrypt 这个 APP 中的方法了
```javascript
import {
  IExamVO,
  IOralPkExerciseVO,
  IOralPkResultVO,
} from '@/types/exercise/exercise';
import request from '@/services/request';
import { encryptRequestBody, DecryptData } from '@/utils/EncryptData';

export default class ExerciseService {
  static getPkExerciseQuestion(pointId: string): Promise<IOralPkExerciseVO> {
    return request
      .post(`/leo-game-pk/{client}/math/pk/match?pointId=${pointId}`, null)
      .then((res) => res.data);
  }
  // 新升级的接口
  @DecryptData
  static getPkExerciseQuestionV2(pointId: string): Promise<IOralPkExerciseVO> {
    return request
      .post(`/leo-game-pk/{client}/math/pk/match/v2?pointId=${pointId}`, null, {
        responseType: 'arraybuffer',
      })
      .then((res) => res.data);
  }

  static postPkExerciseResult(exerciseData: any): Promise<IOralPkResultVO> {
    return encryptRequestBody(exerciseData).then((encryptedData) => {
      return request
        .put('/leo-game-pk/{client}/math/pk/submit', encryptedData, {
          headers: { 'content-type': 'application/octet-stream' },
        })
        .then((res) => res.data);
    });
  }

  static getPkExerciseResult(pkIdStr: string): Promise<IExamVO> {
    return request
      .get(`/leo-game-pk/{client}/math/pk/history/detail?pkIdStr=${pkIdStr}`)
      .then((res) => res.data);
  }
}
```

#### @/components/exercise/Oral.vue#[322-366]
针对大学生的验证，这一看就可以直接 PASS 的，毕竟验证条件只在本地做判断。
```javascript
const NoVerifyPKTimesKey = 'NoVerifyPKTimesKey';
// 单题时间小于'VARIFY_THRESTHOLD'ms 或 距上次校验的时间内PK次数小于'VARIFY_TIMES'次则不校验
const VARIFY_THRESTHOLD = 500;
const VARIFY_TIMES = 5;

const getNoVerifyPKTimes = () => {
  return +StorageUtil.getItem(NoVerifyPKTimesKey) || 0;
};

const reduceNoVerifyPKTimes = () => {
  StorageUtil.setItem(
    NoVerifyPKTimesKey,
    (getNoVerifyPKTimes() - 1).toString()
  );
};

const setNoVerifyPKTimes = () => {
  StorageUtil.setItem(NoVerifyPKTimesKey, VARIFY_TIMES.toString());
};

const isUniversityStudents = () => {
  return new Promise((resolve) => {
    const costTimePerQuestion =
      costTime.value / (exerciseRecord.value?.length ?? 1);
    if (costTimePerQuestion <= VARIFY_THRESTHOLD && !isUltimateChallenge()) {
      if (getNoVerifyPKTimes() <= 0) {
        $addFrog('/event/oralPK/showVerify', {
          costTimePerQuestion: costTimePerQuestion,
        });
        showUniversityStudentVerify.value = true;
        universityRef.value.setModelCallback((isUniversity: boolean) => {
          if (!isUniversity) {
            setNoVerifyPKTimes();
          }
          resolve(isUniversity);
        });
      } else {
        reduceNoVerifyPKTimes();
        resolve(false);
      }
    } else {
      resolve(false);
    }
  });
};

const isUltimateChallenge = () => {
  return Number(StorageUtil.getItem(gradeStorageKey)) === GradeEnum.UNIVERSITY;
};
```

## 思路
了解了代码后我们就可以理顺思路了。
1. **如何获取答案**？使用 Frida 来 hook 上 com.yuanfudao.android.common.webview.base.JsBridgeBean，如果回调函数为 dataDecrypt_ 开头，且上一次调用回调参数中 data['wrappedUrl'].includes('math/pk/match/v2')，则将数据 send 到主程序。
2. **如何进行秒提交**？阅读代码后可以发现在提交对战数据前，会将答题数据存在 LocalStroage 的 exerciseResult 中。那么我们只需要伪造 exerciseResult，再直接打开 result.html，即可实现秒提交，且不用管加密的事情了。什么 Sign 什么 dataEncrypt 的都和我们没关系了。
3. **如何更改答题时间**？答题时间也存储在 exerciseResult 中，所以我们直接更改即可。1000 为 1 秒，测试发现真 0 秒无法提交，但填 1 （0.001秒）则可以正常提交（显示 0.0 秒）。
4. **过大学生验证**？我最开始的思路是更改 NoVerifyPKTimesKey，让其始终为 5，但最后发现验证操作和保存本地结果是在一块的，也就是说我们前面自主打开 result.html 的骚操作一不小心跳过了大学生验证。
5. **如何自主打开 Result.html**？
   通过远程调试在 WebView 中打开通过下面函数获得的链接即可。
   ```javascript
   const getPkResultPageUrl = (pkIdStr) => {
      const url = `https://xyks.yuanfudao.com/bh5/leo-web-oral-pk/result.html?pkIdStr=${pkIdStr}`;
      let nativeUrl = `native://openWebView?url=${encodeURIComponent(
        url
      )}&hideNavigation=true&immerseStatusBar=true&autoHideLoading=false`;
      return nativeUrl;
   };
   ```

## 其它抛弃的思路
1. XPosed 对 APP 本身进行 Hook。在发现是 WebView 套网页后丢弃。
2. 对 WebView 注入代码，通过 Proxy 拦截 window.dataDecrypt_xxx 方法从而拦截解密数据，浅略尝试后无果，故放弃。

## 后话
今天（10/13）打开网页发现，webpack 代码已经看不到了，应该是小猿已经进行了处理。那么后面如果再改代码的话，逆向难度就会提升不少。
