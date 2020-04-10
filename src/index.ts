
import secureRandom from 'secure-random';

import { eddsa as Eddsa } from 'elliptic';

const ec = new Eddsa('ed25519');
const basepoint = ec.g;
const ell = ec.curve.n;

type _point = typeof basepoint;
type _scalar = typeof ell;

export class Scalar {

    constructor(public s: _scalar) {
        this.s = s;
    }

    add(x: Scalar): Scalar {
        return new Scalar(this.s.add(x.s).umod(ell));
    }

    sub(x: Scalar): Scalar {
        return new Scalar(this.s.sub(x.s).umod(ell));
    }

    mul(x: Scalar): Scalar {
        return new Scalar(this.s.mul(x.s).umod(ell));
    }

    inverse(): Scalar {
        return new Scalar(this.s.invm(ell));
    }

    copy(): Scalar {
        return new Scalar(this.s);
    }

    static copy(s: Scalar): Scalar {
        return new Scalar(s);
    }

    toBuffer(): Buffer {
        return Buffer.from(ec.encodeInt(this.s));
    }

    static fromBuffer(buf: Buffer): Scalar {
        const s = ec.decodeInt(buf);
        return new Scalar(s);
    }

    static fromHash(...args: Buffer[]): Scalar {
        const s = ec.hashInt(...args);
        return new Scalar(s);
    }

    static random(): Scalar {
        const sk = secureRandom(32, {type: 'Buffer'});
        return Scalar.fromBuffer(sk);
    }

    equals(s: Scalar): boolean {
        return this.s.eq(s.s);
    }
}

export class Point {

    constructor(public p: _point) {
        this.p = p;
    }

    add(p: Point): Point {
        return new Point(this.p.add(p.p));
    }

    sub(p: Point): Point {
        return new Point(this.p.add(p.p.neg()));
    }

    mul(s: Scalar): Point {
        return new Point(this.p.mul(s.s));
    }

    copy(): Point {
        return new Point(this.p);
    }

    static copy(p: Point): Point {
        return new Point(p);
    }

    static mul(s: Scalar): Point {
        return Point.copy(basepoint).mul(s);
    }

    toBuffer(): Buffer {
        return Buffer.from(ec.encodePoint(this.p));
    }

    static fromBuffer(buf: Buffer): Point {
        const p = ec.decodePoint(Array.from(buf));
        return new Point(p);
    }

    equals(other: Point): boolean {
        return this.p.eq(other.p);
    }
}

export const curve = {
    basepoint: new Point(basepoint),
    pointFromBuffer: (buf: Buffer): Point => Point.fromBuffer(buf),
    randomScalar: (): Scalar => Scalar.random(),
    scalarFromBuffer: (buf: Buffer): Scalar => Scalar.fromBuffer(buf),
    scalarFromHash: (...args: Buffer[]): Scalar => Scalar.fromHash(...args)
};
