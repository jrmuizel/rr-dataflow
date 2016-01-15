Debugging reftests with RR

When debugging reftests it's common to want to trace back the contents of pixel to
see where they came from. I wrote a tool called [rr-dataflow](https://github.com/jrmuizel/rr-dataflow/) to help with this.
rr-dataflow adds an 'origin' command to gdb that you can use to track where data came from.

To use this origin command add it to gdb with something like the following:
(gdb) source rr-dataflow/flow.py

You will need the python bindings for
[capstone](https://github.com/aquynh/capstone) installed. Ubuntu gdb
uses python3 and there's no package for the python3 bindings to capstone, so you'll
need to compile from source.


What follows is a log of a rr session where I use this tool to trace back the contents of a pixel to the code responsible for it being set.
In this case I'm using the softpipe mesa driver which is a simple software implementation of OpenGL. This means that I can trace through
the entire graphics pipeline as needed.

```
Breakpoint 1, mozilla::WebGLContext::ReadPixels (this=0x7fc064bc7000, x=0, y=0, width=64, height=64, format=6408, 
    type=5121, pixels=..., rv=...) at /home/jrmuizel/src/gecko/dom/canvas/WebGLContextGL.cpp:1411
1411	{
(gdb) c
Continuing.

Breakpoint 11, mozilla::ReadPixelsAndConvert (gl=0x7fc05c4e7000, x=0, y=0, width=64, height=64, readFormat=6408, 
    readType=5121, pixelStorePackAlignment=4, destFormat=6408, destType=5121, destBytes=0x7fc05c9d5000)
    at /home/jrmuizel/src/gecko/dom/canvas/WebGLContextGL.cpp:1310
1310	{
(gdb) list
1305	
1306	static void
1307	ReadPixelsAndConvert(gl::GLContext* gl, GLint x, GLint y, GLsizei width, GLsizei height,
1308	                     GLenum readFormat, GLenum readType, size_t pixelStorePackAlignment,
1309	                     GLenum destFormat, GLenum destType, void* destBytes)
1310	{
1311	    if (readFormat == destFormat && readType == destType) {
1312	        gl->fReadPixels(x, y, width, height, destFormat, destType, destBytes);
1313	        return;
1314	    }
(gdb) n
1311	    if (readFormat == destFormat && readType == destType) {
(gdb) 
1312	        gl->fReadPixels(x, y, width, height, destFormat, destType, destBytes);
(gdb) 
1313	        return;
```

Let's disable the two breakpoints and set a watch point on the first pixel of the destination

```
(gdb) dis 1
(gdb) dis 11
(gdb) watch -location *(int*)destBytes
Hardware watchpoint 12: -location *(int*)destBytes
```

Then reverse-continue back to where the first pixel was set.

```
(gdb) rc
Continuing.
Hardware watchpoint 12: -location *(int*)destBytes

Old value = -16711936
New value = 0
__memcpy_avx_unaligned () at ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S:213
213	../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S: No such file or directory.
```
We end up at a memcpy inside of readpixels that copies into the destination buffer.
```
(gdb) bt 9
#0  0x00007fc0ad9ed955 in __memcpy_avx_unaligned () at ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S:213
#1  0x00007fc075c5080f in _mesa_readpixels (__len=<optimized out>, __src=<optimized out>, __dest=<optimized out>)
    at /usr/include/x86_64-linux-gnu/bits/string3.h:53
#2  0x00007fc075c5080f in _mesa_readpixels (packing=0x7fc05c3e92e8, pixels=<optimized out>, type=5121, format=766008576, height=64, width=64, y=0, x=0, ctx=0x7fc05c3ce000) at main/readpix.c:245
#3  0x00007fc075c5080f in _mesa_readpixels (ctx=ctx@entry=0x7fc05c3ce000, x=x@entry=0, y=y@entry=0, width=width@entry=64, height=height@entry=64, format=format@entry=6408, type=5121, packing=0x7fc05c3e92e8, pixels=<optimized out>)
    at main/readpix.c:873
#4  0x00007fc075ce0985 in st_readpixels (ctx=0x7fc05c3ce000, x=0, y=0, width=64, height=64, format=6408, type=5121, pack=0x7fc05c3e92e8, pixels=0x7fc05c9d5000) at state_tracker/st_cb_readpixels.c:255
#5  0x00007fc075c519d4 in _mesa_ReadnPixelsARB (x=0, y=0, width=64, height=64, format=6408, type=5121, bufSize=2147483647, pixels=0x7fc05c9d5000) at main/readpix.c:1120
#6  0x00007fc075c51c82 in _mesa_ReadPixels (x=<optimized out>, y=<optimized out>, width=<optimized out>, height=<optimized out>, format=<optimized out>, type=<optimized out>, pixels=0x7fc05c9d5000) at main/readpix.c:1128
#7  0x00007fc09c3a9b3b in mozilla::gl::GLContext::raw_fReadPixels(int, int, int, int, unsigned int, unsigned int, void*) (this=0x7fc05c4e7000, x=0, y=0, width=64, height=64, format=6408, type=5121, pixels=0x7fc05c9d5000)
    at /home/jrmuizel/src/gecko/gfx/gl/GLContext.h:1511
#8  0x00007fc09c39abe1 in mozilla::gl::GLContext::fReadPixels(int, int, int, int, unsigned int, unsigned int, void*) (this=0x7fc05c4e7000, x=0, y=0, width=64, height=64, format=6408, type=5121, pixels=0x7fc05c9d5000)
    at /home/jrmuizel/src/gecko/gfx/gl/GLContext.cpp:2873
#9  0x00007fc09d78696d in mozilla::ReadPixelsAndConvert(mozilla::gl::GLContext*, GLint, GLint, GLsizei, GLsizei, GLenum, GLenum, size_t, GLenum, GLenum, void*) (gl=0x7fc05c4e7000, x=0, y=0, width=64, height=64, readFormat=6408, readType=5121, pixelStorePackAlignment=4, destFormat=6408, destType=5121, destBytes=0x7fc05c9d5000)
    at /home/jrmuizel/src/gecko/dom/canvas/WebGLContextGL.cpp:1312
```
From here we can see that the memcpy is storing the value of ymm4 into [r10]
We use the `origin` command to step back to the place where ymm4 is loaded.
```
(gdb) origin
0x1000:	vmovdqu	ymmword ptr [r10], ymm4
1
reg used ymm4 

212	in ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S
0x1000:	add	rdx, rdi
211	in ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S
0x1000:	add	edx, eax
210	in ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S
0x1000:	jae	0xfd2
209	in ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S
0x1000:	sub	edx, eax
208	in ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S
0x1000:	add	rdi, rax
207	in ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S
0x1000:	vmovdqa	ymmword ptr [rdi + 0x60], ymm3
206	in ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S
0x1000:	vmovdqa	ymmword ptr [rdi + 0x40], ymm2
205	in ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S
0x1000:	vmovdqa	ymmword ptr [rdi + 0x20], ymm1
204	in ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S
0x1000:	vmovdqa	ymmword ptr [rdi], ymm0
203	in ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S
0x1000:	add	rsi, rax
202	in ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S
0x1000:	vmovdqu	ymm3, ymmword ptr [rsi + 0x60]
201	in ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S
0x1000:	vmovdqu	ymm2, ymmword ptr [rsi + 0x40]
200	in ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S
0x1000:	vmovdqu	ymm1, ymmword ptr [rsi + 0x20]
199	in ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S
0x1000:	vmovdqu	ymm0, ymmword ptr [rsi]
197	in ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S
0x1000:	sub	edx, eax
196	in ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S
0x1000:	add	rsi, r11
195	in ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S
0x1000:	vmovdqu	ymm4, ymmword ptr [rsi]
```
We end up the instruction that loads ymm4 from [rsi]. Origin
does this by single stepping backwards looking for writes to
the ymm4 register. From here we want to continue tracking
the origin. We use the `origin` command again. This time
it sets a hardware watchpoint on the address in rsi.
```
(gdb) origin
0x1000:	vmovdqu	ymm4, ymmword ptr [rsi]
3
mem used *(int*)(0x7fc05c6c5000)
Hardware watchpoint 13: *(int*)(0x7fc05c6c5000)
Hardware watchpoint 13: *(int*)(0x7fc05c6c5000)

Old value = -16711936
New value = -452919552
__memcpy_avx_unaligned () at ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S:238
238	in ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S

We end up in another memcpy. This memcpy is flushing the tile buffer which
is used for rendering to the backbuffer that ReadPixels is reading from.

(gdb) bt 9
#0  0x00007fc0ad9ed9a6 in __memcpy_avx_unaligned () at ../sysdeps/x86_64/multiarch/memcpy-avx-unaligned.S:238
#1  0x00007fc075e89753 in pipe_put_tile_raw (pt=pt@entry=0x7fc05c4f8740, dst=dst@entry=0x7fc05c6c5000, x=x@entry=0, y=y@entry=0, w=<optimized out>, w@entry=64, h=<optimized out>, h@entry=64, src=0x7fc05c9d9000, src_stride=<optimized out>)
    at util/u_tile.c:80
#2  0x00007fc075e8a268 in pipe_put_tile_rgba_format (pt=0x7fc05c4f8740, dst=0x7fc05c6c5000, x=0, y=0, w=w@entry=64, h=h@entry=64, format=PIPE_FORMAT_R8G8B8A8_UNORM, p=0x7fc05c9c5000) at util/u_tile.c:524
#3  0x00007fc0760034aa in sp_flush_tile (tc=tc@entry=0x7fc06c1e9400, pos=pos@entry=0) at sp_tile_cache.c:427
#4  0x00007fc076003c05 in sp_flush_tile_cache (tc=0x7fc06c1e9400) at sp_tile_cache.c:457
#5  0x00007fc075fe6a0e in softpipe_flush (pipe=pipe@entry=0x7fc0650d5000, flags=flags@entry=0, fence=fence@entry=0x7fff2da85b40) at sp_flush.c:72
#6  0x00007fc075fe6b0d in softpipe_flush_resource (pipe=0x7fc0650d5000, texture=texture@entry=0x7fc07fad4380, level=level@entry=0, layer=<optimized out>, flush_flags=flush_flags@entry=0, read_only=<optimized out>, cpu_access=1 '\001', do_not_block=0 '\000') at sp_flush.c:148
#7  0x00007fc07600304f in softpipe_transfer_map (pipe=<optimized out>, resource=0x7fc07fad4380, level=0, usage=1, box=0x7fff2da85bf0, transfer=0x7fc0665e0a58) at sp_texture.c:387
#8  0x00007fc075cdd6bd in st_MapRenderbuffer (transfer=0x7fc0665e0a58, h=64, w=<optimized out>, y=0, x=0, access=<optimized out>, layer=<optimized out>, level=<optimized out>, resource=<optimized out>, context=<optimized out>)
    at ../../src/gallium/auxiliary/util/u_inlines.h:457
#9  0x00007fc075cdd6bd in st_MapRenderbuffer (ctx=<optimized out>, rb=0x7fc0665e09d0, x=0, y=<optimized out>, w=<optimized out>, h=64, mode=1, mapOut=0x7fff2da85cf8, rowStrideOut=0x7fff2da85cf0) at state_tracker/st_cb_fbo.c:772
```
We use the `origin` command again. This time we have rep movsb operation that reads from memory as a source. Origin uses
a hardware watchpoint on that address again.
```
(gdb) origin
0x1000:	rep movsb	byte ptr [rdi], byte ptr [rsi]
3
mem used *(int*)(0x7fc05c9d9003)
Hardware watchpoint 14: *(int*)(0x7fc05c9d9003)
Hardware watchpoint 14: *(int*)(0x7fc05c9d9003)

Old value = 16711935
New value = -437918209
util_format_r8g8b8a8_unorm_pack_rgba_float (dst_row=0x7fc05c9d9000 "", dst_stride=256, src_row=0x7fc05c9c5000, 
    src_stride=<optimized out>, width=64, height=64) at util/u_format_table.c:15204
15204	         *(uint32_t *)dst = value;
```
This watchpoint takes us back to the function that converts from the floating point output of the graphics pipeline
to the byte value that goes in the destination tile.
```
(gdb) bt 9
#0  0x00007fc075eabe44 in util_format_r8g8b8a8_unorm_pack_rgba_float (dst_row=0x7fc05c9d9000 "", dst_stride=256, src_row=0x7fc05c9c5000, src_stride=<optimized out>, width=64, height=64) at util/u_format_table.c:15204
#1  0x00007fc075e8a23b in pipe_put_tile_rgba_format (pt=0x7fc05c4f8740, dst=0x7fc05c6c5000, x=0, y=0, w=w@entry=64, h=h@entry=64, format=PIPE_FORMAT_R8G8B8A8_UNORM, p=0x7fc05c9c5000) at util/u_tile.c:518
#2  0x00007fc0760034aa in sp_flush_tile (tc=tc@entry=0x7fc06c1e9400, pos=pos@entry=0) at sp_tile_cache.c:427
#3  0x00007fc076003c05 in sp_flush_tile_cache (tc=0x7fc06c1e9400) at sp_tile_cache.c:457
#4  0x00007fc075fe6a0e in softpipe_flush (pipe=pipe@entry=0x7fc0650d5000, flags=flags@entry=0, fence=fence@entry=0x7fff2da85b40) at sp_flush.c:72
#5  0x00007fc075fe6b0d in softpipe_flush_resource (pipe=0x7fc0650d5000, texture=texture@entry=0x7fc07fad4380, level=level@entry=0, layer=<optimized out>, flush_flags=flush_flags@entry=0, read_only=<optimized out>, cpu_access=1 '\001', do_not_block=0 '\000') at sp_flush.c:148
#6  0x00007fc07600304f in softpipe_transfer_map (pipe=<optimized out>, resource=0x7fc07fad4380, level=0, usage=1, box=0x7fff2da85bf0, transfer=0x7fc0665e0a58) at sp_texture.c:387
#7  0x00007fc075cdd6bd in st_MapRenderbuffer (transfer=0x7fc0665e0a58, h=64, w=<optimized out>, y=0, x=0, access=<optimized out>, layer=<optimized out>, level=<optimized out>, resource=<optimized out>, context=<optimized out>)
    at ../../src/gallium/auxiliary/util/u_inlines.h:457
#8  0x00007fc075cdd6bd in st_MapRenderbuffer (ctx=<optimized out>, rb=0x7fc0665e09d0, x=0, y=<optimized out>, w=<optimized out>, h=64, mode=1, mapOut=0x7fff2da85cf8, rowStrideOut=0x7fff2da85cf0) at state_tracker/st_cb_fbo.c:772
#9  0x00007fc075c507b2 in _mesa_readpixels (packing=0x7fc05c3e92e8, pixels=0x7fc05c9d5000, type=5121, format=766008576, height=64, width=64, y=0, x=0, ctx=0x7fc05c3ce000) at main/readpix.c:234
```

We see that ecx is being stored into [r10 - 4]. We use `origin` to track back to the source.
```
(gdb) origin
0x1000:	mov	dword ptr [r10 - 4], ecx
1
reg used ecx 

15206	         src += 4;
0x1000:	add	rax, 0x10
15207	         dst += 4;
0x1000:	add	r10, 4
15204	         *(uint32_t *)dst = value;
0x1000:	or	ecx, esi
```
We end at an or instruction. Looking at the source below we see that each of the floating point channels is being converted to a byte.
We'll manually set a watchpoint on the channel that we're interested to avoid getting lost in the conversion code.
```
(gdb) list
15199	         uint32_t value = 0;
15200	         value |= (float_to_ubyte(src[0])) & 0xff;
15201	         value |= ((float_to_ubyte(src[1])) & 0xff) << 8;
15202	         value |= ((float_to_ubyte(src[2])) & 0xff) << 16;
15203	         value |= (float_to_ubyte(src[3])) << 24;
15204	         *(uint32_t *)dst = value;
15205	#endif
15206	         src += 4;
15207	         dst += 4;
15208	      }
(gdb) watch -location src[1]
Hardware watchpoint 15: -location src[1]
(gdb) rc
Continuing.
Hardware watchpoint 15: -location src[1]

Old value = 1
New value = -1.35707841e+23
0x00007fc076003783 in clear_tile_rgba (tile=0x7fc05c9c5000, format=PIPE_FORMAT_R8G8B8A8_UNORM, clear_value=0x7fc06c1e968c)
    at sp_tile_cache.c:272
272	               tile->data.color[i][j][1] = clear_value->f[1];
```
We end up at the clear_tile_rgba function which is settting the data in the buffer from the clear value.
```
(gdb) bt 9
#0  0x00007fc076003783 in clear_tile_rgba (tile=0x7fc05c9c5000, format=
    PIPE_FORMAT_R8G8B8A8_UNORM, clear_value=0x7fc06c1e968c) at sp_tile_cache.c:272
#1  0x00007fc0760040e5 in sp_find_cached_tile (tc=0x7fc06c1e9400, addr=...) at sp_tile_cache.c:579
#2  0x00007fc075febee9 in single_output_color (layer=<optimized out>, y=<optimized out>, x=<optimized out>, tc=<optimized out>) at sp_tile_cache.h:155
#3  0x00007fc075febee9 in single_output_color (qs=0x7fc07fb6c780, quads=0x7fc0665f3500, nr=1) at sp_quad_blend.c:1179
#4  0x00007fc075fefc9f in flush_spans (setup=setup@entry=0x7fc0665f1000) at sp_setup.c:251
#5  0x00007fc075ff0112 in subtriangle (setup=setup@entry=0x7fc0665f1000, eleft=eleft@entry=0x7fc0665f1058, eright=eright@entry=0x7fc0665f1028, lines=64) at sp_setup.c:759
#6  0x00007fc075ff0af2 in sp_setup_tri (setup=setup@entry=0x7fc0665f1000, v0=v0@entry=0x7fc089aea7c0, v1=v1@entry=0x7fc089aea7d0, v2=v2@entry=0x7fc089aea7e0) at sp_setup.c:853
#7  0x00007fc075fe71a2 in sp_vbuf_draw_arrays (vbr=<optimized out>, start=<optimized out>, nr=6) at sp_prim_vbuf.c:422
#8  0x00007fc075e2b704 in draw_pt_emit_linear (emit=<optimized out>, vert_info=<optimized out>, prim_info=0x7fff2da85f80)
    at draw/draw_pt_emit.c:261
#9  0x00007fc075e2d025 in fetch_pipeline_generic (prim_info=0x7fff2da85f80, vert_info=0x7fff2da85e40, emit=<optimized out>) at draw/draw_pt_fetch_shade_pipeline.c:196
```
We use `origin` again twice to track through the store and the load.
```
(gdb) origin
0x1000:	movss	dword ptr [rax - 0xc], xmm0
272	               tile->data.color[i][j][1] = clear_value->f[1];
0x1000:	movss	xmm0, dword ptr [rbp + 4]
(gdb) origin
0x1000:	movss	xmm0, dword ptr [rbp + 4]
3
mem used *(int*)(0x7fc06c1e9690)
Hardware watchpoint 16: *(int*)(0x7fc06c1e9690)
Hardware watchpoint 16: *(int*)(0x7fc06c1e9690)

Old value = 1065353216
New value = 0
sp_tile_cache_clear (tc=0x7fc06c1e9400, color=color@entry=0x7fc05c3cfa4c, clearValue=clearValue@entry=0)
    at sp_tile_cache.c:640
640	   tc->clear_color = *color;
```
We end up in sp_tile_cache_clear which is setting up the clear color.
```
(gdb) bt 9
#0  0x00007fc076004376 in sp_tile_cache_clear (tc=0x7fc06c1e9400, color=color@entry=0x7fc05c3cfa4c, clearValue=clearValue@entry=0) at sp_tile_cache.c:640
#1  0x00007fc075fe5c84 in softpipe_clear (pipe=0x7fc0650d5000, buffers=5, color=0x7fc05c3cfa4c, depth=1, stencil=0)
    at sp_clear.c:71
#2  0x00007fc075cd8181 in st_Clear (ctx=0x7fc05c3ce000, mask=272) at state_tracker/st_cb_clear.c:539
#3  0x00007fc09c3a9427 in mozilla::gl::GLContext::raw_fClear(unsigned int) (this=0x7fc05c4e7000, mask=16640)
    at /home/jrmuizel/src/gecko/gfx/gl/GLContext.h:952
#4  0x00007fc09c3a9456 in mozilla::gl::GLContext::fClear(unsigned int) (this=0x7fc05c4e7000, mask=16640)
    at /home/jrmuizel/src/gecko/gfx/gl/GLContext.h:959
#5  0x00007fc09d7830bf in mozilla::WebGLContext::Clear(unsigned int) (this=0x7fc064bc7000, mask=16640)
    at /home/jrmuizel/src/gecko/dom/canvas/WebGLContextFramebufferOperations.cpp:46
#6  0x00007fc09d202460 in mozilla::dom::WebGLRenderingContextBinding::clear(JSContext*, JS::Handle<JSObject*>, mozilla::WebGLContext*, JSJitMethodCallArgs const&) (cx=0x7fc078086400, obj=..., self=0x7fc064bc7000, args=...)
    at /home/jrmuizel/src/gecko/obj-x86_64-unknown-linux-gnu/dom/bindings/WebGLRenderingContextBinding.cpp:11027
#7  0x00007fc09d6de3fa in mozilla::dom::GenericBindingMethod(JSContext*, unsigned int, JS::Value*) (cx=0x7fc078086400, argc=1, vp=0x7fc08f230210) at /home/jrmuizel/src/gecko/dom/bindings/BindingUtils.cpp:2644
#8  0x00007fc0a03af188 in js::Invoke(JSContext*, JS::CallArgs const&, js::MaybeConstruct) (args=..., native=0x7fc09d6de0bd <mozilla::dom::GenericBindingMethod(JSContext*, unsigned int, JS::Value*)>, cx=0x7fc078086400)
    at /home/jrmuizel/src/gecko/js/src/jscntxtinlines.h:235
#9  0x00007fc0a03af188 in js::Invoke(JSContext*, JS::CallArgs const&, js::MaybeConstruct) (cx=0x7fc078086400, args=..., construct=js::NO_CONSTRUCT) at /home/jrmuizel/src/gecko/js/src/vm/Interpreter.cpp:489
(gdb) 
```

Running a backtrace we see that this goes back to a call to WebGLContext::Clear. This is the actual clear call that triggers the code
that eventually sets the pixel to the value that we see when we call glReadPixels. At this point we've travelled through the entire pipeline, and we've done it
with minimal effort through the magic of [rr](https://github.com/mozilla/rr).
