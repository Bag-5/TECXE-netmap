declare module 'd3-force-3d' {
  export interface SimulationNodeDatum {
    index?: number
    x?: number
    y?: number
    z?: number
    vx?: number
    vy?: number
    vz?: number
    fx?: number | null
    fy?: number | null
    fz?: number | null
  }

  export interface SimulationLinkDatum<NodeT extends SimulationNodeDatum> {
    index?: number
    source: NodeT | string | number
    target: NodeT | string | number
  }

  export interface Simulation<Node extends SimulationNodeDatum> {
    numDimensions(dimensions: number): this
    nodes(nodes: Node[]): this
    force<F = unknown>(name: string, force?: F): this
    force<F = unknown>(name: string): F | undefined
    alpha(): number
    alpha(alpha: number): this
    alphaDecay(decay?: number): this
    stop(): this
    tick(iterations?: number): this
    on(typename: string, listener?: (this: this, ...args: any[]) => void): this
  }

  export function forceSimulation<Node extends SimulationNodeDatum>(
    nodes?: Node[],
    numDimensions?: number
  ): Simulation<Node>

  export function forceX(x?: number): {
    strength(strength: number): { x(n: SimulationNodeDatum): number }
    x(): number
    initialize(nodes: SimulationNodeDatum[]): void
  }

  export function forceY(y?: number): {
    strength(strength: number): { y(n: SimulationNodeDatum): number }
    y(): number
    initialize(nodes: SimulationNodeDatum[]): void
  }

  export function forceZ(z?: number): {
    strength(strength: number): { z(n: SimulationNodeDatum): number }
    z(): number
    initialize(nodes: SimulationNodeDatum[]): void
  }

  export function forceCenter(x?: number, y?: number, z?: number): {
    x(): number
    y(): number
    z(): number
    initialize(nodes: SimulationNodeDatum[]): void
  }

  export function forceManyBody(): {
    strength(strength: number): ReturnType<typeof forceManyBody>
    distanceMin(distance: number): ReturnType<typeof forceManyBody>
    distanceMax(distance: number): ReturnType<typeof forceManyBody>
    initialize(nodes: SimulationNodeDatum[], random?: () => number): void
  }

  export function forceCollide(radius?: number | ((n: SimulationNodeDatum) => number)): {
    radius(radius: number | ((n: SimulationNodeDatum) => number)): ReturnType<typeof forceCollide>
    strength(strength: number): ReturnType<typeof forceCollide>
    iterations(iterations: number): ReturnType<typeof forceCollide>
    initialize(nodes: SimulationNodeDatum[], random?: () => number): void
  }

  export function forceLink<
    Node extends SimulationNodeDatum,
    Link extends { source: Node | string | number; target: Node | string | number } & Record<string, any>,
  >(links?: Link[]): {
    id(idFn: (node: Node, i: number, data: Node[]) => string): ReturnType<
      typeof forceLink<Node, Link>
    >
    distance(distance: number | ((link: Link, i: number, links: Link[]) => number)): ReturnType<
      typeof forceLink<Node, Link>
    >
    strength(strength: number | ((link: Link, i: number, links: Link[]) => number)): ReturnType<
      typeof forceLink<Node, Link>
    >
    iterations(iterations: number): ReturnType<typeof forceLink<Node, Link>>
    links(links: Link[]): ReturnType<typeof forceLink<Node, Link>>
    initialize(nodes: Node[], random?: () => number): void
  }
}
