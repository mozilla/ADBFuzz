/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * The Original Code is ADBFuzz.
 *
 * The Initial Developer of the Original Code is Christian Holler (decoder).
 *
 * Contributors:
 *  Christian Holler <decoder@mozilla.com> (Original Developer)
 *  Jesse Ruderman <jruderman@mozilla.com>
 *  Gary Kwong <gkwong@mozilla.com>
 *
 * ***** END LICENSE BLOCK ***** */

/* 
 * First, we get the output div in our HTML file
 * and setup some logging to that for fancy
 * visualization
 */
var output = document.getElementById("output");
output.style.height = '80%';
var logBuffer = new Array();
function printOutput(message) {
    var pre = document.createElement("p");
    pre.style.wordWrap = "break-word";
    pre.innerHTML = message;
    output.appendChild(pre);

    logBuffer.push(pre);
    if (logBuffer.length > 10) {
        var oldPre = logBuffer.shift();
        output.removeChild(oldPre);
    }
}

var dumpln = function(s) { dump(s + "\n"); printOutput(s); }

/* Parse arguments passed via URL */
var args = new Array();
var params = document.location.href.split('?');
if (params.length > 1) {
    params = params[1].split('&');
    for (pidx in params) { 
        args[params[pidx].split('=')[0]] = params[pidx].split('=')[1];
    }
}

/* Set WebSocket URL */
var wsURL = args['wsurl'];
var ws = undefined;

/* This function initializes Websocket communication */
function initWS(startFunc) {
  if (wsURL) {
      // Firefox doesnt have a WebSocket object
    if (typeof(WebSocket) == "undefined") {
      if (typeof(MozWebSocket) == "undefined") {
        dumpln("Error: No Websocket support found!");
      } else {
        WebSocket = MozWebSocket;
      }
    }

    // Store old dump handler
    var consoleDumpln = dumpln;

    // Open websocket connection and assign callbacks
    ws = new WebSocket(wsURL);
    consoleDumpln("Socket: Attempting connection...");
    ws.onopen = function(evt) {
      consoleDumpln("Socked open");
      // Extend dumpln
      dumpln = function(s) { ws.send(s + "\n"); consoleDumpln(s); }
      startFunc();
    };    
    ws.onclose = function(evt) {
      consoleDumpln("Socked closed");
      // Restore dumpln
      dumpln = consoleDumpln;
    };    
    ws.onmessage = function(evt) { consoleDumpln("Socked received: " + evt.data); };
    ws.onerror = function(evt) {
      consoleDumpln("Socket error: " + evt.data);
      // Restore dumpln
      dumpln = consoleDumpln;
   };
  }
}

/* Random number generation */
var MT = new MersenneTwister19937;
var randSeed = Math.floor(Math.random() * Math.pow(2,28));
dumpln("Seeding PRNG with: " + randSeed);
MT.init_genrand(randSeed);
var rand = function (n) {
    return Math.floor(MT.genrand_real2() * n);
};

/* Simple function that runs code and logs it */
function runCode(code) {
    try {
        /* We need to be able to reproduce, so we need to log our code */
        dumpln("runCode(" + uneval(code) + ");");
        eval(code);
    } catch(e) {
        dumpln(e.toString());
    }

}

/***************************************************************************/

/* Get a reference to our pink square :) */
var square = document.getElementById("square");

function start() {
    // If there is a websocket URL but no socket, initialize websockets first
    // NOTE: start() is called a second time then by the socket's onOpen method.
    if (wsURL && ws == undefined) {
        return initWS(function() { start(); });
    }

    /* Your work goes here, this is just a stupid demo :D */
    var base = "square.style.MozTransform = '";
    var baseEnd = "';";
    var code = base;

    var num = 1 + rand(3);
    for (var i = 0; i < num; ++i) {
        switch(rand(4)) {
            case 0: code += "rotate(" + rand(360) + "deg" + ")"; break;                      // Rotate
            case 1: code += "scale(" + rand(4) + "," + rand(4) + ")"; break;          // Scale
            case 2: code += "skew(" + rand(360) + "deg" + "," + rand(360) + "deg" + ")"; break;      // Skew 
            case 3: code += "translate(" + rand(100) + "," + rand(100) + ")"; break; // Translate
        }
        code += " ";
    }

    code += baseEnd;
    setTimeout(function() { runCode(code); start(); }, 100);
}


/***************************************************************************/


/***************************
 *        PRNG Code        *
 ***************************/

// this program is a JavaScript version of Mersenne Twister, with concealment and encapsulation in class,
// an almost straight conversion from the original program, mt19937ar.c,
// translated by y. okada on July 17, 2006.
// Changes by Jesse Ruderman: added "var" keyword in a few spots; added export_mta etc; pasted into fuzz.js.
// in this program, procedure descriptions and comments of original source code were not removed.
// lines commented with //c// were originally descriptions of c procedure. and a few following lines are appropriate JavaScript descriptions.
// lines commented with /* and */ are original comments.
// lines commented with // are additional comments in this JavaScript version.
// before using this version, create at least one instance of MersenneTwister19937 class, and initialize the each state, given below in c comments, of all the instances.
/*
   A C-program for MT19937, with initialization improved 2002/1/26.
   Coded by Takuji Nishimura and Makoto Matsumoto.

   Before using, initialize the state by using init_genrand(seed)
   or init_by_array(init_key, key_length).

   Copyright (C) 1997 - 2002, Makoto Matsumoto and Takuji Nishimura,
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

     1. Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.

     2. Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.

     3. The names of its contributors may not be used to endorse or promote
        products derived from this software without specific prior written
        permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


   Any feedback is very welcome.
   http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
   email: m-mat @ math.sci.hiroshima-u.ac.jp (remove space)
*/

function MersenneTwister19937() {
    /* Period parameters */
    //c//#define N 624
    //c//#define M 397
    //c//#define MATRIX_A 0x9908b0dfUL   /* constant vector a */
    //c//#define UPPER_MASK 0x80000000UL /* most significant w-r bits */
    //c//#define LOWER_MASK 0x7fffffffUL /* least significant r bits */
    var N = 624;
    var M = 397;
    var MATRIX_A = 0x9908b0df;   /* constant vector a */
    var UPPER_MASK = 0x80000000; /* most significant w-r bits */
    var LOWER_MASK = 0x7fffffff; /* least significant r bits */
    //c//static unsigned long mt[N]; /* the array for the state vector  */
    //c//static int mti=N+1; /* mti==N+1 means mt[N] is not initialized */
    var mt = new Array(N);   /* the array for the state vector  */
    var mti = N+1;           /* mti==N+1 means mt[N] is not initialized */

    function unsigned32 (n1) // returns a 32-bits unsiged integer from an operand to which applied a bit operator.
    {
        return n1 < 0 ? (n1 ^ UPPER_MASK) + UPPER_MASK : n1;
    }

    function subtraction32 (n1, n2) // emulates lowerflow of a c 32-bits unsiged integer variable, instead of the operator -. these both arguments must be non-negative integers expressible using unsigned 32 bits.
    {
        return n1 < n2 ? unsigned32((0x100000000 - (n2 - n1)) & 0xffffffff) : n1 - n2;
    }

    function addition32 (n1, n2) // emulates overflow of a c 32-bits unsiged integer variable, instead of the operator +. these both arguments must be non-negative integers expressible using unsigned 32 bits.
    {
        return unsigned32((n1 + n2) & 0xffffffff)
    }

    function multiplication32 (n1, n2) // emulates overflow of a c 32-bits unsiged integer variable, instead of the operator *. these both arguments must be non-negative integers expressible using unsigned 32 bits.
    {
        var sum = 0;
        for (var i = 0; i < 32; ++i){
            if ((n1 >>> i) & 0x1){
                sum = addition32(sum, unsigned32(n2 << i));
            }
        }
        return sum;
    }

    /* initializes mt[N] with a seed */
    //c//void init_genrand(unsigned long s)
    this.init_genrand = function (s)
    {
        //c//mt[0]= s & 0xffffffff;
        mt[0]= unsigned32(s & 0xffffffff);
        for (mti=1; mti<N; mti++) {
            mt[mti] =
                //c//(1812433253 * (mt[mti-1] ^ (mt[mti-1] >> 30)) + mti);
                addition32(multiplication32(1812433253, unsigned32(mt[mti-1] ^ (mt[mti-1] >>> 30))), mti);
            /* See Knuth TAOCP Vol2. 3rd Ed. P.106 for multiplier. */
            /* In the previous versions, MSBs of the seed affect   */
            /* only MSBs of the array mt[].                        */
            /* 2002/01/09 modified by Makoto Matsumoto             */
            //c//mt[mti] &= 0xffffffff;
            mt[mti] = unsigned32(mt[mti] & 0xffffffff);
            /* for >32 bit machines */
        }
    }

    /* initialize by an array with array-length */
    /* init_key is the array for initializing keys */
    /* key_length is its length */
    /* slight change for C++, 2004/2/26 */
    //c//void init_by_array(unsigned long init_key[], int key_length)
    this.init_by_array = function (init_key, key_length)
    {
        //c//int i, j, k;
        var i, j, k;
        //c//init_genrand(19650218);
        this.init_genrand(19650218);
        i=1; j=0;
        k = (N>key_length ? N : key_length);
        for (; k; k--) {
            //c//mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1664525))
            //c//	+ init_key[j] + j; /* non linear */
            mt[i] = addition32(addition32(unsigned32(mt[i] ^ multiplication32(unsigned32(mt[i-1] ^ (mt[i-1] >>> 30)), 1664525)), init_key[j]), j);
            mt[i] =
                //c//mt[i] &= 0xffffffff; /* for WORDSIZE > 32 machines */
                unsigned32(mt[i] & 0xffffffff);
            i++; j++;
            if (i>=N) { mt[0] = mt[N-1]; i=1; }
            if (j>=key_length) j=0;
        }
        for (k=N-1; k; k--) {
            //c//mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1566083941))
            //c//- i; /* non linear */
            mt[i] = subtraction32(unsigned32((dbg=mt[i]) ^ multiplication32(unsigned32(mt[i-1] ^ (mt[i-1] >>> 30)), 1566083941)), i);
            //c//mt[i] &= 0xffffffff; /* for WORDSIZE > 32 machines */
            mt[i] = unsigned32(mt[i] & 0xffffffff);
            i++;
            if (i>=N) { mt[0] = mt[N-1]; i=1; }
        }
        mt[0] = 0x80000000; /* MSB is 1; assuring non-zero initial array */
    }

    this.export_state = function() { return [mt, mti]; };
    this.import_state = function(s) { mt = s[0]; mti = s[1]; };
    this.export_mta = function() { return mt; };
    this.import_mta = function(_mta) { mt = _mta };
    this.export_mti = function() { return mti; };
    this.import_mti = function(_mti) { mti = _mti; }

    /* generates a random number on [0,0xffffffff]-interval */
    //c//unsigned long genrand_int32(void)
    this.genrand_int32 = function ()
    {
        //c//unsigned long y;
        //c//static unsigned long mag01[2]={0x0UL, MATRIX_A};
        var y;
        var mag01 = new Array(0x0, MATRIX_A);
        /* mag01[x] = x * MATRIX_A  for x=0,1 */

        if (mti >= N) { /* generate N words at one time */
            //c//int kk;
            var kk;

            if (mti == N+1)   /* if init_genrand() has not been called, */
                //c//init_genrand(5489); /* a default initial seed is used */
                this.init_genrand(5489); /* a default initial seed is used */

            for (kk=0;kk<N-M;kk++) {
                //c//y = (mt[kk]&UPPER_MASK)|(mt[kk+1]&LOWER_MASK);
                //c//mt[kk] = mt[kk+M] ^ (y >> 1) ^ mag01[y & 0x1];
                y = unsigned32((mt[kk]&UPPER_MASK)|(mt[kk+1]&LOWER_MASK));
                mt[kk] = unsigned32(mt[kk+M] ^ (y >>> 1) ^ mag01[y & 0x1]);
            }
            for (;kk<N-1;kk++) {
                //c//y = (mt[kk]&UPPER_MASK)|(mt[kk+1]&LOWER_MASK);
                //c//mt[kk] = mt[kk+(M-N)] ^ (y >> 1) ^ mag01[y & 0x1];
                y = unsigned32((mt[kk]&UPPER_MASK)|(mt[kk+1]&LOWER_MASK));
                mt[kk] = unsigned32(mt[kk+(M-N)] ^ (y >>> 1) ^ mag01[y & 0x1]);
            }
            //c//y = (mt[N-1]&UPPER_MASK)|(mt[0]&LOWER_MASK);
            //c//mt[N-1] = mt[M-1] ^ (y >> 1) ^ mag01[y & 0x1];
            y = unsigned32((mt[N-1]&UPPER_MASK)|(mt[0]&LOWER_MASK));
            mt[N-1] = unsigned32(mt[M-1] ^ (y >>> 1) ^ mag01[y & 0x1]);
            mti = 0;
        }

        y = mt[mti++];

        /* Tempering */
        //c//y ^= (y >> 11);
        //c//y ^= (y << 7) & 0x9d2c5680;
        //c//y ^= (y << 15) & 0xefc60000;
        //c//y ^= (y >> 18);
        y = unsigned32(y ^ (y >>> 11));
        y = unsigned32(y ^ ((y << 7) & 0x9d2c5680));
        y = unsigned32(y ^ ((y << 15) & 0xefc60000));
        y = unsigned32(y ^ (y >>> 18));

        return y;
    }

    /* generates a random number on [0,0x7fffffff]-interval */
    //c//long genrand_int31(void)
    this.genrand_int31 = function ()
    {
        //c//return (genrand_int32()>>1);
        return (this.genrand_int32()>>>1);
    }

    /* generates a random number on [0,1]-real-interval */
    //c//double genrand_real1(void)
    this.genrand_real1 = function ()
    {
        //c//return genrand_int32()*(1.0/4294967295.0);
        return this.genrand_int32()*(1.0/4294967295.0);
        /* divided by 2^32-1 */
    }

    /* generates a random number on [0,1)-real-interval */
    //c//double genrand_real2(void)
    this.genrand_real2 = function ()
    {
        //c//return genrand_int32()*(1.0/4294967296.0);
        return this.genrand_int32()*(1.0/4294967296.0);
        /* divided by 2^32 */
    }

    /* generates a random number on (0,1)-real-interval */
    //c//double genrand_real3(void)
    this.genrand_real3 = function ()
    {
        //c//return ((genrand_int32()) + 0.5)*(1.0/4294967296.0);
        return ((this.genrand_int32()) + 0.5)*(1.0/4294967296.0);
        /* divided by 2^32 */
    }

    /* generates a random number on [0,1) with 53-bit resolution*/
    //c//double genrand_res53(void)
    this.genrand_res53 = function ()
    {
        //c//unsigned long a=genrand_int32()>>5, b=genrand_int32()>>6;
        var a=this.genrand_int32()>>>5, b=this.genrand_int32()>>>6;
        return(a*67108864.0+b)*(1.0/9007199254740992.0);
    }
    /* These real versions are due to Isaku Wada, 2002/01/09 added */
}

/***************************
 *    End of PRNG Code     *
 ***************************/


/* For reproduction, your logged code will go here, see README */
// SPLICE
start();
// SPLICE